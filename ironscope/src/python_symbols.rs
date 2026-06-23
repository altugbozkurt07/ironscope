use anyhow::{anyhow, bail, Context, Result};
use goblin::elf::Elf;
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize)]
pub struct PythonContract {
    #[serde(default)]
    pub python: Option<ContractPythonInfo>,
    #[serde(default)]
    pub verification: Option<ContractVerification>,
    pub libpython: LibPythonInfo,
    pub asyncio_module: ModuleInfo,
    pub python_binary: ModuleInfo,
    pub symbols: HashMap<String, SymbolEntry>,
    pub offsets: OffsetsMap,
    pub frame_state_values: FrameStateValues,
    pub task_state_values: TaskStateValues,
    pub contract_version: u32,
    pub generated_ns: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractPythonInfo {
    pub implementation: String,
    pub version: String,
    pub arch: String,
    pub build_id: String,
    #[serde(default)]
    pub sha256_fallback: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractVerification {
    pub state: String,
    #[serde(default)]
    pub verifier: String,
    #[serde(default)]
    pub verified_ns: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LibPythonInfo {
    pub path: PathBuf,
    pub build_id: String,
    #[serde(default)]
    pub build_id_fallback_sha256: String,
    #[serde(default)]
    pub arch: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ModuleInfo {
    pub path: PathBuf,
    pub build_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SymbolEntry {
    pub source: String,
    pub file_offset: u64,
    /// Present for `_PyEval_EvalFrameDefault`: file offset of the
    /// `start_frame:` label inside the function body. We attach the
    /// uprobe here rather than at the function entry, because CPython
    /// 3.12 dispatches inlined Python-to-Python calls via
    /// `goto start_frame;` rather than re-entering the function.
    #[serde(default)]
    pub start_frame_file_offset: Option<u64>,
    #[serde(default)]
    pub start_frame_extra_file_offsets: Vec<u64>,
    #[serde(default)]
    pub start_frame_offset_source: Option<String>,
    /// Present for `_PyEval_EvalFrameDefault`: aarch64 callee-saved
    /// register index (19..28) that holds `frame` at `start_frame:`.
    #[serde(default)]
    pub frame_reg_idx: Option<u8>,
    /// Symbol size from .dynsym (bytes).
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub end_return_value_file_offset: Option<u64>,
    #[serde(default)]
    pub end_return_value_frame_reg_idx: Option<u8>,
    #[serde(default)]
    pub end_return_value_offset_source: Option<String>,
    #[serde(default)]
    pub end_return_const_file_offset: Option<u64>,
    #[serde(default)]
    pub end_return_const_frame_reg_idx: Option<u8>,
    #[serde(default)]
    pub end_return_const_offset_source: Option<String>,
    #[serde(default)]
    pub end_exception_file_offset: Option<u64>,
    #[serde(default)]
    pub end_exception_frame_reg_idx: Option<u8>,
    #[serde(default)]
    pub end_exception_offset_source: Option<String>,
    #[serde(default)]
    pub yield_value_file_offset: Option<u64>,
    #[serde(default)]
    pub resume_file_offset: Option<u64>,
    #[serde(default)]
    pub resume_offset_source: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OffsetsMap {
    #[serde(rename = "PyObject")]
    pub py_object: PyObjectOffsets,
    #[serde(rename = "PyCodeObject")]
    pub code_object: CodeObjectOffsets,
    #[serde(rename = "PyUnicodeObject")]
    pub unicode_object: UnicodeObjectOffsets,
    #[serde(rename = "_PyInterpreterFrame")]
    pub interp_frame: InterpFrameOffsets,
    #[serde(rename = "PyGenObject")]
    pub gen_object: GenObjectOffsets,
    #[serde(rename = "TaskObj")]
    pub task_obj: TaskObjOffsets,
    #[serde(rename = "PyThreadState", default)]
    pub thread_state: ThreadStateOffsets,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PyObjectOffsets {
    pub ob_type: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CodeObjectOffsets {
    pub co_filename: u32,
    pub co_name: u32,
    pub co_qualname: u32,
    pub co_firstlineno: u32,
    #[serde(default)]
    pub co_flags: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnicodeObjectOffsets {
    pub compact_data: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InterpFrameOffsets {
    pub f_executable: u32,
    pub previous: u32,
    pub owner: u32,
    pub localsplus: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenObjectOffsets {
    pub gi_frame_state: u32,
    pub gi_iframe: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TaskObjOffsets {
    pub task_state: u32,
    pub task_coro: u32,
    pub task_result: u32,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ThreadStateOffsets {
    #[serde(default)]
    pub current_frame: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FrameStateValues {
    #[serde(rename = "CREATED")]
    pub created: i8,
    #[serde(rename = "SUSPENDED")]
    pub suspended: i8,
    #[serde(rename = "EXECUTING")]
    pub executing: i8,
    #[serde(rename = "COMPLETED")]
    pub completed: i8,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TaskStateValues {
    #[serde(rename = "PENDING")]
    pub pending: u8,
    #[serde(rename = "CANCELLED")]
    pub cancelled: u8,
    #[serde(rename = "FINISHED")]
    pub finished: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedPythonRuntime {
    pub pid: u32,
    pub python_path: PathBuf,
    pub asyncio_path: PathBuf,
    pub python_build_id: String,
    pub python_sha256: String,
    pub asyncio_build_id: String,
    pub arch: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractIndex {
    pub version: u32,
    pub contracts: Vec<ContractIndexEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractIndexEntry {
    pub path: PathBuf,
    pub python_build_id: String,
    pub asyncio_build_id: String,
    pub arch: String,
    #[serde(default)]
    pub python_version: String,
}

#[derive(Debug)]
pub struct ResolvedPythonContract {
    pub contract: PythonContract,
    pub detected: DetectedPythonRuntime,
}

impl PythonContract {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read contract: {}", path.display()))?;
        let contract: PythonContract = serde_json::from_str(&data)
            .with_context(|| format!("cannot parse contract: {}", path.display()))?;
        if contract.contract_version != 1 && contract.contract_version != 2 {
            bail!(
                "unsupported contract version {} (expected 1 or 2)",
                contract.contract_version
            );
        }
        Ok(contract)
    }

    pub fn symbol_offset(&self, name: &str) -> Result<u64> {
        self.symbols
            .get(name)
            .map(|s| s.file_offset)
            .ok_or_else(|| anyhow!("symbol '{}' not in contract", name))
    }

    pub fn symbol_binary(&self, name: &str) -> Result<&Path> {
        let entry = self
            .symbols
            .get(name)
            .ok_or_else(|| anyhow!("symbol '{}' not in contract", name))?;
        match entry.source.as_str() {
            s if s.starts_with("libpython") || s.starts_with("python_binary") => {
                Ok(&self.libpython.path)
            }
            "callscan" | "asyncio_symtab" => Ok(&self.asyncio_module.path),
            other => Err(anyhow!("unknown symbol source '{}' for '{}'", other, name)),
        }
    }

    pub fn validate_attach_provenance(&self) -> Result<()> {
        let eval = self
            .symbols
            .get("_PyEval_EvalFrameDefault")
            .context("contract missing _PyEval_EvalFrameDefault")?;

        require_offset(
            "_PyEval_EvalFrameDefault.start_frame_file_offset",
            eval.start_frame_file_offset,
            eval.start_frame_offset_source.as_deref(),
        )?;
        eval.frame_reg_idx
            .context("contract missing _PyEval_EvalFrameDefault.frame_reg_idx")?;
        require_offset(
            "_PyEval_EvalFrameDefault.end_return_value_file_offset",
            eval.end_return_value_file_offset,
            eval.end_return_value_offset_source.as_deref(),
        )?;
        require_offset(
            "_PyEval_EvalFrameDefault.end_return_const_file_offset",
            eval.end_return_const_file_offset,
            eval.end_return_const_offset_source.as_deref(),
        )?;
        require_offset(
            "_PyEval_EvalFrameDefault.end_exception_file_offset",
            eval.end_exception_file_offset,
            eval.end_exception_offset_source.as_deref(),
        )?;
        require_offset(
            "_PyEval_EvalFrameDefault.resume_file_offset",
            eval.resume_file_offset,
            eval.resume_offset_source.as_deref(),
        )?;

        for name in [
            "_asyncio_Task___init___impl",
            "task_step",
            "task_eager_start",
            "PyGen_Type_tp_dealloc",
            "PyCoro_Type_tp_dealloc",
            "PyAsyncGen_Type_tp_dealloc",
        ] {
            let sym = self
                .symbols
                .get(name)
                .with_context(|| format!("contract missing {}", name))?;
            if sym.source.contains("heuristic") {
                bail!("contract symbol {} uses unsupported heuristic source", name);
            }
        }

        Ok(())
    }

    pub fn validate_runtime_loadable(&self) -> Result<()> {
        self.validate_attach_provenance()?;
        if self
            .verification
            .as_ref()
            .map(|v| v.state.as_str() == "verified")
            .unwrap_or(false)
        {
            return Ok(());
        }
        bail!(
            "contract is not runtime-loadable: attach offsets are present but contract verification.state is not 'verified'"
        )
    }
}

fn require_offset(label: &str, offset: Option<u64>, source: Option<&str>) -> Result<()> {
    offset.with_context(|| format!("contract missing {}", label))?;
    let source = source.with_context(|| format!("contract missing provenance for {}", label))?;
    if source.trim().is_empty() {
        bail!("contract has empty provenance for {}", label);
    }
    if source.contains("heuristic") {
        bail!(
            "contract {} uses unsupported heuristic provenance '{}'",
            label,
            source
        );
    }
    Ok(())
}

fn read_build_id(path: &Path) -> Result<Option<String>> {
    let data =
        std::fs::read(path).with_context(|| format!("cannot read ELF: {}", path.display()))?;
    let elf = Elf::parse(&data).with_context(|| format!("cannot parse ELF: {}", path.display()))?;

    for shdr in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(shdr.sh_name).unwrap_or("");
        if name != ".note.gnu.build-id" {
            continue;
        }
        let start = shdr.sh_offset as usize;
        let end = start + shdr.sh_size as usize;
        if end > data.len() || shdr.sh_size < 16 {
            continue;
        }
        let namesz = u32::from_le_bytes(data[start..start + 4].try_into().unwrap()) as usize;
        let descsz = u32::from_le_bytes(data[start + 4..start + 8].try_into().unwrap()) as usize;
        let desc_start = start + 12 + ((namesz + 3) & !3);
        let desc_end = desc_start + descsz;
        if desc_end <= end {
            let hex: String = data[desc_start..desc_end]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            return Ok(Some(hex));
        }
    }
    Ok(None)
}

fn sha256sum(path: &Path) -> Result<String> {
    let output = std::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .with_context(|| format!("cannot run sha256sum on {}", path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("sha256sum produced no output for {}", path.display()))
}

fn check_no_gil(pid: u32) -> Result<bool> {
    let environ_path = format!("/proc/{}/environ", pid);
    match std::fs::read(&environ_path) {
        Ok(data) => {
            for var in data.split(|&b| b == 0) {
                if var == b"PYTHON_GIL=0" {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(e) => {
            warn!(
                "cannot read {}: {} — assuming GIL is enabled",
                environ_path, e
            );
            Ok(false)
        }
    }
}

fn elf_arch(path: &Path) -> Result<String> {
    let data =
        std::fs::read(path).with_context(|| format!("cannot read ELF: {}", path.display()))?;
    let elf = Elf::parse(&data).with_context(|| format!("cannot parse ELF: {}", path.display()))?;
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_X86_64 => "x86_64",
        other => return Ok(format!("elf-machine-{}", other)),
    };
    Ok(arch.to_string())
}

fn read_build_id_or_sha256(path: &Path) -> Result<(String, String)> {
    match read_build_id(path)? {
        Some(build_id) if !build_id.is_empty() => Ok((build_id, String::new())),
        _ => Ok((String::new(), sha256sum(path)?)),
    }
}

fn mapped_python_binary(pid: u32) -> Result<PathBuf> {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .with_context(|| format!("cannot read /proc/{}/exe", pid))?;
    if exe.exists() {
        return Ok(exe);
    }

    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("cannot read {}", maps_path))?;
    for line in content.lines() {
        if !line.contains("r-xp") {
            continue;
        }
        if let Some(path_str) = line.split_whitespace().last() {
            let path = PathBuf::from(path_str);
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("python") && path.exists() {
                return Ok(path);
            }
        }
    }
    Err(anyhow!(
        "cannot identify mapped Python executable for pid {}",
        pid
    ))
}

fn elf_has_symbols(path: &Path, required: &[&str]) -> Result<bool> {
    let data =
        std::fs::read(path).with_context(|| format!("cannot read ELF: {}", path.display()))?;
    let elf = Elf::parse(&data).with_context(|| format!("cannot parse ELF: {}", path.display()))?;
    let mut found = vec![false; required.len()];

    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            for (idx, required_name) in required.iter().enumerate() {
                if name == *required_name {
                    found[idx] = true;
                }
            }
        }
    }
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            for (idx, required_name) in required.iter().enumerate() {
                if name == *required_name {
                    found[idx] = true;
                }
            }
        }
    }

    Ok(found.into_iter().all(|hit| hit))
}

fn mapped_asyncio_module(pid: u32) -> Result<PathBuf> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("cannot read {}", maps_path))?;
    for line in content.lines() {
        if !line.contains("_asyncio") || !line.contains(".so") {
            continue;
        }
        if let Some(path_str) = line.split_whitespace().last() {
            let path = PathBuf::from(path_str);
            if path.exists() {
                return Ok(path);
            }
        }
    }
    Err(anyhow!(
        "cannot identify mapped _asyncio module for pid {}",
        pid
    ))
}

pub fn detect_runtime_for_pid(pid: u32) -> Result<DetectedPythonRuntime> {
    if check_no_gil(pid)? {
        bail!(
            "pid {} has PYTHON_GIL=0 (free-threaded build); refusing to attach",
            pid
        );
    }
    let python_path = mapped_python_binary(pid)?;
    let asyncio_path = match mapped_asyncio_module(pid) {
        Ok(path) => path,
        Err(err) => {
            let required = [
                "PyInit__asyncio",
                "task_step",
                "_asyncio_Task___init___impl",
            ];
            if elf_has_symbols(&python_path, &required)? {
                warn!(
                    "no mapped _asyncio extension for pid {}; using Python executable for built-in _asyncio task probes",
                    pid
                );
                python_path.clone()
            } else {
                return Err(err);
            }
        }
    };
    let (python_build_id, python_sha256) = read_build_id_or_sha256(&python_path)?;
    let (asyncio_build_id, asyncio_sha256) = read_build_id_or_sha256(&asyncio_path)?;
    let asyncio_identity = if asyncio_build_id.is_empty() {
        asyncio_sha256
    } else {
        asyncio_build_id
    };
    if python_build_id.is_empty() && python_sha256.is_empty() {
        bail!(
            "cannot identify Python binary build id or SHA256 for pid {}",
            pid
        );
    }
    if asyncio_identity.is_empty() {
        bail!(
            "cannot identify _asyncio build id or SHA256 for pid {}",
            pid
        );
    }
    let arch = elf_arch(&python_path)?;
    Ok(DetectedPythonRuntime {
        pid,
        python_path,
        asyncio_path,
        python_build_id,
        python_sha256,
        asyncio_build_id: asyncio_identity,
        arch,
    })
}

fn contract_python_build_id(contract: &PythonContract) -> &str {
    contract
        .python
        .as_ref()
        .map(|p| p.build_id.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(contract.libpython.build_id.as_str())
}

fn contract_arch(contract: &PythonContract) -> &str {
    contract
        .python
        .as_ref()
        .map(|p| p.arch.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(contract.libpython.arch.as_str())
}

pub fn contract_matches_detected(
    contract: &PythonContract,
    detected: &DetectedPythonRuntime,
) -> bool {
    let python_match = contract_python_build_id(contract) == detected.python_build_id
        || (!contract.libpython.build_id_fallback_sha256.is_empty()
            && contract.libpython.build_id_fallback_sha256 == detected.python_sha256);
    python_match
        && contract.asyncio_module.build_id == detected.asyncio_build_id
        && contract_arch(contract) == detected.arch
}

fn rewrite_contract_runtime_paths(
    mut contract: PythonContract,
    detected: &DetectedPythonRuntime,
) -> PythonContract {
    contract.libpython.path = detected.python_path.clone();
    contract.python_binary.path = detected.python_path.clone();
    contract.asyncio_module.path = detected.asyncio_path.clone();
    contract
}

fn load_contract_index(dir: &Path) -> Result<Option<ContractIndex>> {
    let index_path = dir.join("index.json");
    if !index_path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&index_path)
        .with_context(|| format!("cannot read contract index: {}", index_path.display()))?;
    let index: ContractIndex = serde_json::from_str(&data)
        .with_context(|| format!("cannot parse contract index: {}", index_path.display()))?;
    Ok(Some(index))
}

pub fn load_contract_for_detected(
    dir: &Path,
    detected: DetectedPythonRuntime,
) -> Result<ResolvedPythonContract> {
    if let Some(index) = load_contract_index(dir)? {
        for entry in index.contracts {
            if entry.python_build_id != detected.python_build_id
                || entry.asyncio_build_id != detected.asyncio_build_id
                || entry.arch != detected.arch
            {
                continue;
            }
            let path = if entry.path.is_absolute() {
                entry.path
            } else {
                dir.join(entry.path)
            };
            let contract = PythonContract::load(&path)?;
            if contract_matches_detected(&contract, &detected) {
                contract.validate_runtime_loadable()?;
                return Ok(ResolvedPythonContract {
                    contract: rewrite_contract_runtime_paths(contract, &detected),
                    detected,
                });
            }
        }
    }

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("cannot read contract dir: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some("index.json") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let contract = PythonContract::load(&path)?;
        if contract_matches_detected(&contract, &detected) {
            contract.validate_runtime_loadable()?;
            return Ok(ResolvedPythonContract {
                contract: rewrite_contract_runtime_paths(contract, &detected),
                detected,
            });
        }
    }

    bail!(
        "unsupported CPython profile for pid {}: python_build_id={} asyncio_build_id={} arch={} (searched {})",
        detected.pid,
        detected.python_build_id,
        detected.asyncio_build_id,
        detected.arch,
        dir.display()
    )
}

pub fn load_contract_for_pid(dir: &Path, pid: u32) -> Result<ResolvedPythonContract> {
    let detected = detect_runtime_for_pid(pid)?;
    load_contract_for_detected(dir, detected)
}

#[cfg(test)]
pub fn write_contract_index_entry(
    dir: &Path,
    contract_path: &Path,
    contract: &PythonContract,
) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create contract dir: {}", dir.display()))?;
    let index_path = dir.join("index.json");
    let mut index = if index_path.exists() {
        load_contract_index(dir)?.unwrap_or(ContractIndex {
            version: 1,
            contracts: Vec::new(),
        })
    } else {
        ContractIndex {
            version: 1,
            contracts: Vec::new(),
        }
    };
    let rel_path = contract_path
        .strip_prefix(dir)
        .unwrap_or(contract_path)
        .to_path_buf();
    let entry = ContractIndexEntry {
        path: rel_path,
        python_build_id: contract_python_build_id(contract).to_string(),
        asyncio_build_id: contract.asyncio_module.build_id.clone(),
        arch: contract_arch(contract).to_string(),
        python_version: contract
            .python
            .as_ref()
            .map(|p| p.version.clone())
            .unwrap_or_default(),
    };
    index.contracts.retain(|e| {
        !(e.python_build_id == entry.python_build_id
            && e.asyncio_build_id == entry.asyncio_build_id
            && e.arch == entry.arch)
    });
    index.contracts.push(entry);
    let data = serde_json::to_string_pretty(&index)?;
    std::fs::write(&index_path, data)
        .with_context(|| format!("cannot write {}", index_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_contract() -> PythonContract {
        serde_json::from_str(
            r#"{
              "python": {
                "implementation": "cpython",
                "version": "3.12.3",
                "arch": "aarch64",
                "build_id": "python-build",
                "sha256_fallback": "python-sha"
              },
              "libpython": {
                "path": "/packaged/python",
                "build_id": "legacy-build",
                "build_id_fallback_sha256": "python-sha",
                "arch": "aarch64"
              },
              "asyncio_module": {
                "path": "/packaged/_asyncio.so",
                "build_id": "asyncio-build"
              },
              "python_binary": {
                "path": "/packaged/python",
                "build_id": "python-build"
              },
              "symbols": {
                "_PyEval_EvalFrameDefault": {
                  "source": "python_binary",
                  "file_offset": 100,
                  "start_frame_file_offset": 120,
                  "start_frame_offset_source": "validated-test",
                  "frame_reg_idx": 19,
                  "end_return_value_file_offset": 200,
                  "end_return_value_offset_source": "validated-test",
                  "end_return_const_file_offset": 240,
                  "end_return_const_offset_source": "validated-test",
                  "end_exception_file_offset": 280,
                  "end_exception_offset_source": "validated-test",
                  "resume_file_offset": 360,
                  "resume_offset_source": "validated-test"
                },
                "_asyncio_Task___init___impl": {
                  "source": "asyncio_symtab",
                  "file_offset": 400
                },
                "task_step": {
                  "source": "asyncio_symtab",
                  "file_offset": 440
                },
                "task_eager_start": {
                  "source": "asyncio_symtab",
                  "file_offset": 480
                },
                "PyGen_Type_tp_dealloc": {
                  "source": "libpython_runtime_read",
                  "file_offset": 520
                },
                "PyCoro_Type_tp_dealloc": {
                  "source": "libpython_runtime_read",
                  "file_offset": 560
                },
                "PyAsyncGen_Type_tp_dealloc": {
                  "source": "libpython_runtime_read",
                  "file_offset": 600
                }
              },
              "offsets": {
                "PyObject": {"ob_type": 8},
                "PyCodeObject": {"co_filename": 1, "co_name": 2, "co_qualname": 3, "co_firstlineno": 4},
                "PyUnicodeObject": {"compact_data": 48},
                "_PyInterpreterFrame": {"f_executable": 0, "previous": 8, "owner": 16, "localsplus": 72},
                "PyGenObject": {"gi_frame_state": 176, "gi_iframe": 184},
                "TaskObj": {"task_state": 48, "task_coro": 64, "task_result": 72},
                "PyThreadState": {"current_frame": 72}
              },
              "frame_state_values": {"CREATED": -2, "SUSPENDED": -1, "EXECUTING": 0, "COMPLETED": 1},
              "task_state_values": {"PENDING": 0, "CANCELLED": 1, "FINISHED": 2},
              "contract_version": 2,
              "generated_ns": 1
            }"#,
        )
        .expect("sample contract parses")
    }

    fn detected() -> DetectedPythonRuntime {
        DetectedPythonRuntime {
            pid: 42,
            python_path: PathBuf::from("/live/python"),
            asyncio_path: PathBuf::from("/live/_asyncio.so"),
            python_build_id: "python-build".to_string(),
            python_sha256: "python-sha".to_string(),
            asyncio_build_id: "asyncio-build".to_string(),
            arch: "aarch64".to_string(),
        }
    }

    fn temp_contract_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("ironscope-contract-test-{nanos}"))
    }

    #[test]
    fn contract_match_requires_build_ids_and_arch() {
        let mut runtime = detected();
        let contract = sample_contract();
        assert!(contract_matches_detected(&contract, &runtime));

        runtime.python_build_id = "other-python".to_string();
        assert!(contract_matches_detected(&contract, &runtime));

        runtime.python_sha256 = "other-sha".to_string();
        assert!(!contract_matches_detected(&contract, &runtime));

        runtime = detected();
        runtime.asyncio_build_id = "other-asyncio".to_string();
        assert!(!contract_matches_detected(&contract, &runtime));

        runtime = detected();
        runtime.arch = "x86_64".to_string();
        assert!(!contract_matches_detected(&contract, &runtime));
    }

    #[test]
    fn contract_validation_rejects_heuristic_attach_offsets() {
        let mut contract = sample_contract();
        let eval = contract
            .symbols
            .get_mut("_PyEval_EvalFrameDefault")
            .expect("sample eval symbol");
        eval.resume_offset_source = Some("aarch64-cpython312-heuristic".to_string());

        let err = contract
            .validate_attach_provenance()
            .expect_err("heuristic attach offsets must fail closed");
        assert!(err.to_string().contains("heuristic"));
    }

    #[test]
    fn runtime_loading_rejects_unverified_generated_attach_sources() {
        let mut contract = sample_contract();
        let eval = contract
            .symbols
            .get_mut("_PyEval_EvalFrameDefault")
            .expect("sample eval symbol");
        eval.start_frame_offset_source = Some("pattern-crossjump-fanin".to_string());
        eval.resume_offset_source = Some("pattern-bytecode-resume".to_string());
        eval.end_return_value_offset_source = Some("pattern-return-value".to_string());
        eval.end_return_const_offset_source = Some("pattern-return-const".to_string());
        eval.end_exception_offset_source = Some("pattern-exception-unwind".to_string());

        let err = contract
            .validate_runtime_loadable()
            .expect_err("generated-only contract must not be runtime-loadable");
        assert!(err.to_string().contains("not runtime-loadable"));
    }

    #[test]
    fn runtime_loading_accepts_verified_generated_attach_sources() {
        let mut contract = sample_contract();
        let eval = contract
            .symbols
            .get_mut("_PyEval_EvalFrameDefault")
            .expect("sample eval symbol");
        eval.start_frame_offset_source = Some("pattern-crossjump-fanin".to_string());
        eval.resume_offset_source = Some("pattern-bytecode-resume".to_string());
        eval.end_return_value_offset_source = Some("pattern-return-value".to_string());
        eval.end_return_const_offset_source = Some("pattern-return-const".to_string());
        eval.end_exception_offset_source = Some("pattern-exception-unwind".to_string());
        contract.verification = Some(ContractVerification {
            state: "verified".to_string(),
            verifier: "test".to_string(),
            verified_ns: 1,
        });

        contract
            .validate_runtime_loadable()
            .expect("verified generated contract is runtime-loadable");
    }

    #[test]
    fn load_contract_uses_index_and_rewrites_runtime_paths() {
        let dir = temp_contract_dir();
        fs::create_dir_all(&dir).expect("create contract dir");
        let contract_path = dir.join("contract.json");
        let mut contract = sample_contract();
        contract.verification = Some(ContractVerification {
            state: "verified".to_string(),
            verifier: "unit-test".to_string(),
            verified_ns: 1,
        });
        fs::write(
            &contract_path,
            serde_json::to_string_pretty(&contract).expect("serialize contract"),
        )
        .expect("write contract");
        write_contract_index_entry(&dir, &contract_path, &contract).expect("write index");

        let runtime = detected();
        let resolved =
            load_contract_for_detected(&dir, runtime.clone()).expect("load matching contract");
        assert_eq!(resolved.detected.pid, runtime.pid);
        assert_eq!(resolved.contract.libpython.path, runtime.python_path);
        assert_eq!(resolved.contract.python_binary.path, runtime.python_path);
        assert_eq!(resolved.contract.asyncio_module.path, runtime.asyncio_path);

        fs::remove_dir_all(&dir).expect("remove contract dir");
    }

    #[test]
    fn load_contract_fails_closed_without_matching_profile() {
        let dir = temp_contract_dir();
        fs::create_dir_all(&dir).expect("create contract dir");
        let contract_path = dir.join("contract.json");
        let contract = sample_contract();
        fs::write(
            &contract_path,
            serde_json::to_string_pretty(&contract).expect("serialize contract"),
        )
        .expect("write contract");
        write_contract_index_entry(&dir, &contract_path, &contract).expect("write index");

        let mut runtime = detected();
        runtime.python_build_id = "unsupported-python".to_string();
        runtime.python_sha256 = "unsupported-sha".to_string();
        let err = load_contract_for_detected(&dir, runtime).expect_err("unsupported profile fails");
        assert!(err.to_string().contains("unsupported CPython profile"));

        fs::remove_dir_all(&dir).expect("remove contract dir");
    }
}
