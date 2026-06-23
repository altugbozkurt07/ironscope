use super::process_reader::ProcessReader;
use super::resolver::CpythonResolver;
use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

const MAX_UNICODE_BYTES: usize = 16 * 1024;
const MAX_C_STRING: usize = 4096;
const MAX_DICT_ENTRIES: i64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PythonVersion {
    pub major: u8,
    pub minor: u8,
    pub micro: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpythonOffsets {
    pub ob_type: u64,
    pub unicode_length: u64,
    pub unicode_state: u64,
    pub unicode_compact_ascii_data: u64,
    pub unicode_compact_non_ascii_data: u64,
    pub type_tp_name: u64,
    pub type_tp_basicsize: u64,
    pub type_tp_itemsize: u64,
    pub type_tp_dictoffset: u64,
    pub managed_dict_ptr_from_object: i64,
    pub dict_ma_used: u64,
    pub dict_ma_keys: u64,
    pub dict_ma_values: u64,
    pub dict_keys_log2_size: u64,
    pub dict_keys_log2_index_bytes: u64,
    pub dict_keys_kind: u64,
    pub dict_keys_nentries: u64,
    pub dict_keys_indices: u64,
    pub dict_key_entry_size: u64,
    pub dict_unicode_entry_size: u64,
    pub dict_key_entry_key: u64,
    pub dict_key_entry_value: u64,
    pub dict_unicode_entry_key: u64,
    pub dict_unicode_entry_value: u64,
    pub code_filename: u64,
    pub code_qualname: u64,
    pub frame_executable: u64,
    pub frame_localsplus: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpythonProfile {
    pub version: PythonVersion,
    pub pointer_width: u8,
    pub debug_build: bool,
    pub offsets: CpythonOffsets,
}

#[derive(Debug)]
pub struct DetectedPython {
    pub version: PythonVersion,
    pub pointer_width: u8,
}

pub struct LiveCpythonResolver {
    reader: ProcessReader,
    profile: CpythonProfile,
}

impl LiveCpythonResolver {
    pub fn new(reader: ProcessReader, profile: CpythonProfile) -> Self {
        Self { reader, profile }
    }

    pub fn detect_for_pid(pid: u32) -> Result<(Self, DetectedPython)> {
        let reader = ProcessReader::new(pid);
        let detected = detect_python_for_pid(&reader)?;
        let profile = CpythonProfile::for_version(detected.version, detected.pointer_width)?;
        Ok((Self::new(reader, profile), detected))
    }

    #[cfg(test)]
    pub fn profile(&self) -> &CpythonProfile {
        &self.profile
    }

    fn read_usize(&self, addr: u64) -> Result<u64> {
        match self.profile.pointer_width {
            8 => self.reader.read_u64(addr),
            4 => self.reader.read_u32(addr).map(u64::from),
            other => bail!("unsupported pointer width: {}", other),
        }
    }

    fn read_isize(&self, addr: u64) -> Result<i64> {
        match self.profile.pointer_width {
            8 => self.reader.read_i64(addr),
            4 => self.reader.read_u32(addr).map(|v| v as i32 as i64),
            other => bail!("unsupported pointer width: {}", other),
        }
    }

    fn read_dict_value_from_split_values(&self, values: u64, index: i64) -> Result<Option<u64>> {
        if index < 0 {
            return Ok(None);
        }
        let ptr_addr = values + (index as u64 * self.profile.pointer_width as u64);
        let value = self.read_usize(ptr_addr)?;
        Ok((value != 0).then_some(value))
    }

    fn read_negative_dictoffset_dict(
        &self,
        obj: u64,
        type_ptr: u64,
        dictoffset: i64,
    ) -> Result<u64> {
        let itemsize = self.read_isize(type_ptr + self.profile.offsets.type_tp_itemsize)?;
        if itemsize != 0 {
            bail!("unsupported negative tp_dictoffset for variable-size object {obj:#x}");
        }
        let basicsize = self.read_isize(type_ptr + self.profile.offsets.type_tp_basicsize)?;
        let dict_offset = basicsize
            .checked_add(dictoffset)
            .ok_or_else(|| anyhow!("negative tp_dictoffset overflow for object {obj:#x}"))?;
        if dict_offset >= 0 {
            self.read_usize(obj + dict_offset as u64)
        } else {
            self.read_usize(
                obj.checked_sub(dict_offset.unsigned_abs()).ok_or_else(|| {
                    anyhow!("negative tp_dictoffset underflow for object {obj:#x}")
                })?,
            )
        }
    }
}

impl CpythonResolver for LiveCpythonResolver {
    fn read_type_ptr(&self, obj: u64) -> Result<u64> {
        self.read_usize(obj + self.profile.offsets.ob_type)
    }

    fn read_type_name(&self, obj: u64) -> Result<String> {
        let type_ptr = self.read_type_ptr(obj)?;
        let tp_name = self.read_usize(type_ptr + self.profile.offsets.type_tp_name)?;
        self.reader.read_c_string(tp_name, MAX_C_STRING)
    }

    fn read_unicode(&self, obj: u64) -> Result<String> {
        let len = self.read_isize(obj + self.profile.offsets.unicode_length)?;
        if len < 0 {
            bail!("negative unicode length at {obj:#x}: {len}");
        }
        let len = len as usize;
        if len > MAX_UNICODE_BYTES {
            bail!("unicode object at {obj:#x} too large: {len} code points");
        }

        let state = self
            .reader
            .read_u32(obj + self.profile.offsets.unicode_state)?;
        let kind = (state >> 2) & 0b111;
        let compact = ((state >> 5) & 1) == 1;
        let ascii = ((state >> 6) & 1) == 1;
        if !compact {
            bail!("unsupported non-compact unicode object at {obj:#x}");
        }

        let (data_addr, width) = if ascii {
            (
                obj + self.profile.offsets.unicode_compact_ascii_data,
                1usize,
            )
        } else {
            let width = match kind {
                1 => 1usize,
                2 => 2usize,
                4 => 4usize,
                other => bail!("unsupported unicode kind {other} at {obj:#x}"),
            };
            (
                obj + self.profile.offsets.unicode_compact_non_ascii_data,
                width,
            )
        };

        let byte_len = len
            .checked_mul(width)
            .ok_or_else(|| anyhow!("unicode byte length overflow"))?;
        if byte_len > MAX_UNICODE_BYTES {
            bail!("unicode object at {obj:#x} too large: {byte_len} bytes");
        }
        let mut buf = vec![0u8; byte_len];
        self.reader.read_exact_at(data_addr, &mut buf)?;

        match width {
            1 => String::from_utf8(buf).context("PyUnicode UCS1/ASCII data is not UTF-8"),
            2 => {
                let units: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16(&units).context("PyUnicode UCS2 data is not valid UTF-16")
            }
            4 => {
                let mut out = String::new();
                for chunk in buf.chunks_exact(4) {
                    let cp = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let ch =
                        char::from_u32(cp).ok_or_else(|| anyhow!("invalid UCS4 codepoint {cp}"))?;
                    out.push(ch);
                }
                Ok(out)
            }
            _ => unreachable!(),
        }
    }

    fn read_dict_item(&self, dict: u64, key: &str) -> Result<Option<u64>> {
        let used = self.read_isize(dict + self.profile.offsets.dict_ma_used)?;
        if used <= 0 {
            return Ok(None);
        }
        let keys = self.read_usize(dict + self.profile.offsets.dict_ma_keys)?;
        let values = self.read_usize(dict + self.profile.offsets.dict_ma_values)?;
        if keys == 0 {
            return Ok(None);
        }

        let kind = self
            .reader
            .read_u8(keys + self.profile.offsets.dict_keys_kind)?;
        let index_bytes_log2 = self
            .reader
            .read_u8(keys + self.profile.offsets.dict_keys_log2_index_bytes)?;
        let index_bytes = 1u64
            .checked_shl(u32::from(index_bytes_log2))
            .ok_or_else(|| anyhow!("invalid dict index byte log2: {index_bytes_log2}"))?;
        let nentries = self.read_isize(keys + self.profile.offsets.dict_keys_nentries)?;
        if !(0..=MAX_DICT_ENTRIES).contains(&nentries) {
            bail!("unsupported dict entry count {nentries}");
        }

        let entries = align_up(
            keys + self.profile.offsets.dict_keys_indices + index_bytes,
            8,
        );
        for idx in 0..nentries {
            let (key_ptr, value_ptr) = if kind == 1 || kind == 2 {
                let entry = entries + idx as u64 * self.profile.offsets.dict_unicode_entry_size;
                let key_ptr =
                    self.read_usize(entry + self.profile.offsets.dict_unicode_entry_key)?;
                let value_ptr = if values == 0 {
                    self.read_usize(entry + self.profile.offsets.dict_unicode_entry_value)?
                } else {
                    self.read_dict_value_from_split_values(values, idx)?
                        .unwrap_or(0)
                };
                (key_ptr, value_ptr)
            } else {
                let entry = entries + idx as u64 * self.profile.offsets.dict_key_entry_size;
                let key_ptr = self.read_usize(entry + self.profile.offsets.dict_key_entry_key)?;
                let value_ptr =
                    self.read_usize(entry + self.profile.offsets.dict_key_entry_value)?;
                (key_ptr, value_ptr)
            };

            if key_ptr == 0 || value_ptr == 0 {
                continue;
            }
            if self.read_unicode(key_ptr).unwrap_or_default() == key {
                return Ok(Some(value_ptr));
            }
        }
        Ok(None)
    }

    fn read_attr(&self, obj: u64, key: &str) -> Result<Option<u64>> {
        let type_ptr = self.read_type_ptr(obj)?;
        let dictoffset = self.read_isize(type_ptr + self.profile.offsets.type_tp_dictoffset)?;
        if dictoffset == 0 {
            return Ok(None);
        }
        let dict_ptr =
            if dictoffset == -1 {
                let offset = self.profile.offsets.managed_dict_ptr_from_object;
                if offset >= 0 {
                    self.read_usize(obj + offset as u64)?
                } else {
                    self.read_usize(obj.checked_sub(offset.unsigned_abs()).ok_or_else(|| {
                        anyhow!("managed dict offset underflow for object {obj:#x}")
                    })?)?
                }
            } else if dictoffset > 0 {
                self.read_usize(obj + dictoffset as u64)?
            } else {
                let managed = self.profile.offsets.managed_dict_ptr_from_object;
                let managed_addr = if managed >= 0 {
                    obj.checked_add(managed as u64)
                } else {
                    obj.checked_sub(managed.unsigned_abs())
                };
                if let Some(addr) = managed_addr {
                    if let Ok(candidate) = self.read_usize(addr) {
                        if candidate != 0
                            && self
                                .read_type_name(candidate)
                                .map(|name| name == "dict")
                                .unwrap_or(false)
                        {
                            candidate
                        } else {
                            self.read_negative_dictoffset_dict(obj, type_ptr, dictoffset)?
                        }
                    } else {
                        self.read_negative_dictoffset_dict(obj, type_ptr, dictoffset)?
                    }
                } else {
                    self.read_negative_dictoffset_dict(obj, type_ptr, dictoffset)?
                }
            };
        if dict_ptr == 0 {
            return Ok(None);
        }
        self.read_dict_item(dict_ptr, key)
    }

    fn read_code_filename(&self, code: u64) -> Result<String> {
        let ptr = self.read_usize(code + self.profile.offsets.code_filename)?;
        self.read_unicode(ptr)
    }

    fn read_code_qualname(&self, code: u64) -> Result<String> {
        let ptr = self.read_usize(code + self.profile.offsets.code_qualname)?;
        self.read_unicode(ptr)
    }
}

pub fn detect_python_for_pid(reader: &ProcessReader) -> Result<DetectedPython> {
    let executable = reader.exe_path()?;
    let output = Command::new(&executable)
        .arg("-c")
        .arg("import json, struct, sys; print(json.dumps({'version': sys.version_info[:3], 'pointer_width': struct.calcsize('P')}))")
        .output()
        .with_context(|| format!("cannot execute {} to detect CPython version", executable.display()))?;
    if !output.status.success() {
        bail!(
            "python version detection failed for {}: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "invalid python version probe output from {}",
            executable.display()
        )
    })?;
    let version = value
        .get("version")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("python version probe did not return version array"))?;
    if version.len() != 3 {
        bail!("python version probe returned invalid version array: {version:?}");
    }
    let get_u8 = |idx: usize| -> Result<u8> {
        let n = version[idx]
            .as_u64()
            .ok_or_else(|| anyhow!("version element {idx} is not an integer"))?;
        u8::try_from(n).context("version element out of u8 range")
    };
    let pointer_width = value
        .get("pointer_width")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("python version probe did not return pointer_width"))?;
    let pointer_width = u8::try_from(pointer_width).context("pointer_width out of u8 range")?;
    Ok(DetectedPython {
        version: PythonVersion {
            major: get_u8(0)?,
            minor: get_u8(1)?,
            micro: get_u8(2)?,
        },
        pointer_width,
    })
}

impl CpythonProfile {
    pub fn for_version(version: PythonVersion, pointer_width: u8) -> Result<Self> {
        if version.major != 3 {
            bail!("unsupported Python major version: {}", version.major);
        }
        match version.minor {
            12 if pointer_width == 8 => Ok(crate::python_runtime::cpython_312::profile(version)),
            other => bail!("unsupported CPython resolver profile: 3.{other}"),
        }
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    #[derive(Debug, Deserialize)]
    struct FixtureAddrs {
        pid: u32,
        text_ptr: u64,
        dict_ptr: u64,
        obj_ptr: u64,
        code_ptr: u64,
    }

    struct PythonFixture {
        child: Child,
        addrs: FixtureAddrs,
    }

    impl Drop for PythonFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn python_bin() -> String {
        if let Ok(python) = std::env::var("PYTHON") {
            return python;
        }
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("ironscope crate should have workspace parent");
        let venv = workspace.join(".venv-e2e-v1/bin/python");
        if venv.exists() {
            venv.to_string_lossy().to_string()
        } else {
            "python3".to_string()
        }
    }

    fn spawn_fixture() -> Result<PythonFixture> {
        let script = r#"
import json, os, time
from types import SimpleNamespace
obj = SimpleNamespace()
obj.name = 'ironscope_attr'
text = 'hello_unicode'
d = {'needle': 'dict_value'}
def sample_function():
    return 'ok'
print(json.dumps({
    'pid': os.getpid(),
    'text_ptr': id(text),
    'dict_ptr': id(d),
    'obj_ptr': id(obj),
    'code_ptr': id(sample_function.__code__),
}), flush=True)
time.sleep(30)
"#;
        let mut child = Command::new(python_bin())
            .arg("-c")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn python resolver fixture")?;
        let stdout = child.stdout.take().context("fixture stdout missing")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("read fixture json line")?;
        let addrs: FixtureAddrs = serde_json::from_str(&line).context("parse fixture json")?;
        Ok(PythonFixture { child, addrs })
    }

    fn resolver_for_fixture(fixture: &PythonFixture) -> Result<LiveCpythonResolver> {
        let (resolver, detected) = LiveCpythonResolver::detect_for_pid(fixture.addrs.pid)?;
        if detected.version.minor != 12 {
            bail!(
                "test fixture requires the V0.1 CPython 3.12 resolver profile, got {:?}",
                detected.version
            );
        }
        Ok(resolver)
    }

    #[test]
    fn unsupported_profile_fails_closed() {
        let err = CpythonProfile::for_version(
            PythonVersion {
                major: 3,
                minor: 9,
                micro: 18,
            },
            8,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported CPython resolver profile"));
    }

    #[test]
    fn resolver_profiles_are_limited_to_v0_1_supported_cpython_minor() {
        for minor in [10, 11, 13] {
            let err = CpythonProfile::for_version(
                PythonVersion {
                    major: 3,
                    minor,
                    micro: 0,
                },
                8,
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("unsupported CPython resolver profile"),
                "unexpected error for 3.{minor}: {err}"
            );
        }

        let profile = CpythonProfile::for_version(
            PythonVersion {
                major: 3,
                minor: 12,
                micro: 3,
            },
            8,
        )
        .expect("3.12 resolver profile should be available for V0.1");
        assert_eq!(profile.version.minor, 12);
    }

    #[test]
    fn resolves_type_name_unicode_dict_attr_and_code_fields() -> Result<()> {
        let fixture = spawn_fixture()?;
        let resolver = resolver_for_fixture(&fixture)?;

        assert_eq!(resolver.profile().version.minor, 12);
        assert_eq!(resolver.read_type_name(fixture.addrs.text_ptr)?, "str");
        assert_eq!(
            resolver.read_unicode(fixture.addrs.text_ptr)?,
            "hello_unicode"
        );

        let dict_value = resolver
            .read_dict_item(fixture.addrs.dict_ptr, "needle")?
            .context("dict item not found")?;
        assert_eq!(resolver.read_unicode(dict_value)?, "dict_value");

        let attr_value = resolver
            .read_attr(fixture.addrs.obj_ptr, "name")?
            .context("object attr not found")?;
        assert_eq!(resolver.read_unicode(attr_value)?, "ironscope_attr");

        let filename = resolver.read_code_filename(fixture.addrs.code_ptr)?;
        assert!(
            filename == "<string>" || filename.ends_with(".py"),
            "unexpected code filename: {filename}"
        );
        assert_eq!(
            resolver.read_code_qualname(fixture.addrs.code_ptr)?,
            "sample_function"
        );
        Ok(())
    }
}
