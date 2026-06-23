use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Minimal process memory reader used by the userspace CPython resolver.
///
/// The resolver is intentionally userspace-only: eBPF captures shallow object
/// pointers and this reader performs the expensive/deep object inspection.
#[derive(Clone, Debug)]
pub struct ProcessReader {
    pid: libc::pid_t,
}

impl ProcessReader {
    pub fn new(pid: u32) -> Self {
        Self {
            pid: pid as libc::pid_t,
        }
    }

    pub fn exe_path(&self) -> Result<PathBuf> {
        std::fs::read_link(format!("/proc/{}/exe", self.pid))
            .with_context(|| format!("cannot read /proc/{}/exe", self.pid))
    }

    pub fn read_exact_at(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        if addr == 0 {
            bail!("cannot read from null process address");
        }

        match self.read_process_vm(addr, out) {
            Ok(()) => Ok(()),
            Err(primary) => self
                .read_proc_mem(addr, out)
                .with_context(|| format!("process_vm_readv failed first: {primary:#}")),
        }
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact_at(addr, &mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(addr, &mut buf)?;
        Ok(u32::from_ne_bytes(buf))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(addr, &mut buf)?;
        Ok(u64::from_ne_bytes(buf))
    }

    pub fn read_i64(&self, addr: u64) -> Result<i64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(addr, &mut buf)?;
        Ok(i64::from_ne_bytes(buf))
    }

    pub fn read_c_string(&self, addr: u64, max_len: usize) -> Result<String> {
        if max_len == 0 {
            bail!("max_len must be non-zero");
        }
        let mut buf = vec![0u8; max_len];
        self.read_exact_at(addr, &mut buf)?;
        let len = buf.iter().position(|b| *b == 0).unwrap_or(max_len);
        String::from_utf8(buf[..len].to_vec()).context("target C string is not UTF-8")
    }

    fn read_process_vm(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        let local = libc::iovec {
            iov_base: out.as_mut_ptr().cast(),
            iov_len: out.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: out.len(),
        };
        let read = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("process_vm_readv failed");
        }
        if read as usize != out.len() {
            bail!("short process_vm_readv read: {} != {}", read, out.len());
        }
        Ok(())
    }

    fn read_proc_mem(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        let mut file = File::open(format!("/proc/{}/mem", self.pid))
            .with_context(|| format!("cannot open /proc/{}/mem", self.pid))?;
        file.seek(SeekFrom::Start(addr))
            .with_context(|| format!("cannot seek target memory to {addr:#x}"))?;
        file.read_exact(out)
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("cannot read target memory at {addr:#x}"))
    }
}
