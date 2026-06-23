mod compiler;
mod config;
mod final_state;
mod python_runtime;
mod python_symbols;
mod rules;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::maps::lpm_trie::LpmTrie;
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{BtfTracePoint, FEntry, Lsm, UProbe};
use aya::{Btf, Ebpf};
use clap::{Parser, Subcommand};
use log::{debug, info, warn};

use compiler::PolicyCompiler;
use config::IronScopeYamlConfig;
use ironscope_common::types::*;

#[derive(Parser, Debug)]
#[command(name = "ironscope", about = "eBPF runtime enforcement for LLM agents")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML configuration file (optional — runs with defaults if omitted)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override enforcement mode (monitor or enforce)
    #[arg(short, long)]
    mode: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Directory containing validated CPython contracts.
    #[arg(long)]
    contract_dir: Option<PathBuf>,

    /// Framework root-rule file for CPython frame classification.
    #[arg(long)]
    framework_rules: Option<PathBuf>,

    /// Ready marker written after the runtime attaches and policy state is loaded.
    #[arg(long, default_value = "/tmp/ironscope/ready")]
    ready_file: PathBuf,

    /// JSON output file for cpython runtime results.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Max runtime duration in seconds. 0 means run until stopped.
    #[arg(long, default_value = "0")]
    duration: u64,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Detect and validate CPython runtime contracts.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ProfileCommand {
    /// Print target process Python build identity.
    Detect {
        /// Target Python agent process id.
        #[arg(long)]
        pid: u32,
    },
    /// Validate that a contract matches the target process build and required offsets.
    Validate {
        /// Target Python agent process id.
        #[arg(long)]
        pid: u32,
        /// Contract JSON to validate.
        #[arg(long)]
        contract: PathBuf,
    },
}

async fn run_command(command: &Commands) -> Result<()> {
    match command {
        Commands::Profile { command } => run_profile_command(command).await,
    }
}

async fn run_profile_command(command: &ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::Detect { pid } => {
            let detected = python_symbols::detect_runtime_for_pid(*pid)?;
            println!("{}", serde_json::to_string_pretty(&detected)?);
            Ok(())
        }
        ProfileCommand::Validate { pid, contract } => {
            let detected = python_symbols::detect_runtime_for_pid(*pid)?;
            let loaded = python_symbols::PythonContract::load(contract)?;
            if !python_symbols::contract_matches_detected(&loaded, &detected) {
                bail!(
                    "contract {} does not match target pid {} (python_build_id={} asyncio_build_id={} arch={})",
                    contract.display(),
                    pid,
                    detected.python_build_id,
                    detected.asyncio_build_id,
                    detected.arch
                );
            }
            loaded.validate_attach_provenance()?;
            println!(
                "CONTRACT_VALIDATED pid={} contract={}",
                pid,
                contract.display()
            );
            Ok(())
        }
    }
}

fn default_contract_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("IRONSCOPE_CONTRACT_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    dirs.push(PathBuf::from("/usr/share/ironscope/python-contracts"));
    if let Some(workspace_root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() {
        dirs.push(workspace_root.join("tools/python-contracts"));
    }
    dirs
}

fn resolve_contract_dir(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        if dir.exists() {
            return Ok(dir.clone());
        }
        bail!("contract directory does not exist: {}", dir.display());
    }
    for dir in default_contract_dirs() {
        if dir.exists() {
            return Ok(dir);
        }
    }
    bail!("no CPython contract directory found; use --contract-dir or IRONSCOPE_CONTRACT_DIR")
}

fn default_framework_rule_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("IRONSCOPE_FRAMEWORK_RULES") {
        paths.push(PathBuf::from(path));
    }
    paths.push(PathBuf::from(
        "/usr/share/ironscope/rules/framework_rules.yaml",
    ));
    if let Some(workspace_root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent() {
        paths.push(workspace_root.join("tools/rules/framework_rules.yaml"));
    }
    paths
}

fn resolve_framework_rules(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.clone());
        }
        bail!("framework rules file does not exist: {}", path.display());
    }
    for path in default_framework_rule_paths() {
        if path.exists() {
            return Ok(path);
        }
    }
    bail!("framework rules file not found; use --framework-rules or IRONSCOPE_FRAMEWORK_RULES")
}

fn configured_agent_pids(config: &config::IronScopeSection) -> Result<Vec<u32>> {
    let pids: Vec<u32> = config.agents.iter().filter_map(|a| a.pid).collect();
    if pids.is_empty() {
        bail!("v0.1 CPython runtime requires at least one ironscope.agents[].pid");
    }
    Ok(pids)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    if let Some(command) = &args.command {
        return run_command(command).await;
    }

    info!("IronScope starting...");

    run_cpython_runtime(&args).await
}

fn attach_tracepoints(ebpf: &mut Ebpf, btf: &Btf) -> Result<()> {
    let prog: &mut BtfTracePoint = ebpf.program_mut("sched_process_fork").unwrap().try_into()?;
    prog.load("sched_process_fork", btf)?;
    prog.attach()?;
    info!("attached BTF tracepoint: sched_process_fork");

    let prog: &mut BtfTracePoint = ebpf.program_mut("sched_process_exit").unwrap().try_into()?;
    prog.load("sched_process_exit", btf)?;
    prog.attach()?;
    info!("attached BTF tracepoint: sched_process_exit");

    let prog: &mut BtfTracePoint = ebpf.program_mut("sched_process_exec").unwrap().try_into()?;
    prog.load("sched_process_exec", btf)?;
    prog.attach()?;
    info!("attached BTF tracepoint: sched_process_exec");

    Ok(())
}

fn attach_lsm_hooks(ebpf: &mut Ebpf, btf: &Btf) -> Result<()> {
    let prog: &mut Lsm = ebpf.program_mut("ag_file_open").unwrap().try_into()?;
    prog.load("file_open", btf)?;
    prog.attach()?;

    let prog: &mut Lsm = ebpf.program_mut("ag_bprm_check").unwrap().try_into()?;
    prog.load("bprm_check_security", btf)?;
    prog.attach()?;

    let prog: &mut Lsm = ebpf.program_mut("ag_socket_connect").unwrap().try_into()?;
    prog.load("socket_connect", btf)?;
    prog.attach()?;

    Ok(())
}

fn attach_fentry_probes(ebpf: &mut Ebpf, btf: &Btf) -> Result<()> {
    let prog: &mut FEntry = ebpf
        .program_mut("ag_fentry_file_open")
        .unwrap()
        .try_into()?;
    prog.load("security_file_open", btf)?;
    prog.attach()?;

    let prog: &mut FEntry = ebpf
        .program_mut("ag_fentry_bprm_check")
        .unwrap()
        .try_into()?;
    prog.load("security_bprm_check", btf)?;
    prog.attach()?;

    let prog: &mut FEntry = ebpf
        .program_mut("ag_fentry_socket_connect")
        .unwrap()
        .try_into()?;
    prog.load("security_socket_connect", btf)?;
    prog.attach()?;

    Ok(())
}

/// When running under sudo, chown a file back to the real user so
/// non-root cleanup (rm -f) in verification scripts works in /tmp/.
fn chown_to_real_user(path: &std::path::Path) {
    #[cfg(unix)]
    {
        let uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
        let gid: Option<u32> = std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok());
        if let (Some(uid), Some(gid)) = (uid, gid) {
            use std::os::unix::ffi::OsStrExt;
            let mut buf = path.as_os_str().as_bytes().to_vec();
            buf.push(0);
            unsafe { libc::chown(buf.as_ptr() as *const libc::c_char, uid, gid) };
        }
    }
}

fn populate_maps(ebpf: &mut Ebpf, compiled: &compiler::CompiledPolicy) -> Result<()> {
    // FS policy
    let mut fs_policy: AyaHashMap<&mut MapData, ToolPolicyKey, u8> = AyaHashMap::try_from(
        ebpf.map_mut("TOOL_FS_POLICY")
            .context("TOOL_FS_POLICY not found")?,
    )?;
    for (key, perm) in &compiled.fs_rules {
        fs_policy.insert(key, perm, 0)?;
    }
    info!("populated {} FS policy rules", compiled.fs_rules.len());

    // Exec policy
    let mut exec_policy: AyaHashMap<&mut MapData, ToolExecKey, u8> = AyaHashMap::try_from(
        ebpf.map_mut("TOOL_EXEC_POLICY")
            .context("TOOL_EXEC_POLICY not found")?,
    )?;
    for (key, perm) in &compiled.exec_rules {
        exec_policy.insert(key, perm, 0)?;
    }
    info!("populated {} exec policy rules", compiled.exec_rules.len());

    // Network policy (LPM trie)
    let mut net_policy: LpmTrie<&mut MapData, ToolNetData, u8> = LpmTrie::try_from(
        ebpf.map_mut("TOOL_NET_POLICY")
            .context("TOOL_NET_POLICY not found")?,
    )?;
    for (key, perm) in &compiled.net_rules {
        let data = ToolNetData {
            tool_id: key.tool_id,
            addr: key.addr,
            port: key.port,
            _pad: key._pad,
        };
        let lpm_key = aya::maps::lpm_trie::Key::new(key.prefixlen, data);
        net_policy.insert(&lpm_key, perm, 0)?;
    }
    info!("populated {} net policy rules", compiled.net_rules.len());

    // Protected agent scope. BPF LSM hooks are global, so the kernel program
    // must know which configured agent TGIDs are allowed to reach policy.
    let mut protected_tgids: AyaHashMap<&mut MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.map_mut("PROTECTED_TGIDS")
            .context("PROTECTED_TGIDS not found")?,
    )?;
    for pid in &compiled.agent_pids {
        let one: u8 = 1;
        protected_tgids.insert(pid, &one, 0)?;
        info!("seeded protected agent PID {}", pid);
    }
    if compiled.agent_pids.is_empty() {
        warn!("no configured agent PID; enforcement will not apply until agent scope is seeded");
    }

    // Config
    let mut config_map: AyaHashMap<&mut MapData, u32, IronScopeConfig> = AyaHashMap::try_from(
        ebpf.map_mut("IRONSCOPE_CONFIG")
            .context("IRONSCOPE_CONFIG not found")?,
    )?;
    config_map.insert(
        &0,
        &IronScopeConfig {
            mode: compiled.mode,
            discover: 1,
            unattributed_policy: UNATTRIBUTED_AUDIT_ONLY,
            unknown_tool_policy: compiled.unknown_tool_policy,
            resolver_error_policy: compiled.resolver_error_policy,
            child_scope: compiled.child_scope,
            default_tool_policy: compiled.default_tool_policy,
            _pad: [0; 1],
        },
        0,
    )?;
    info!("set enforcement mode: {}", compiled.mode);

    Ok(())
}

fn mark_tool_ctx_resolver_error(ctx: &mut ToolCtx) {
    ctx.tool_id = TOOL_IDLE;
    ctx.flags &= !TOOL_CTX_FLAG_RESOLVED;
    ctx.flags |= TOOL_CTX_FLAG_RESOLVER_ERROR;
    ctx.generation = ctx.generation.wrapping_add(1);
}

fn mark_tool_ctx_map_resolver_error(
    tool_ctx_map: &mut AyaHashMap<MapData, u64, ToolCtx>,
    ctx_id: u64,
) -> Result<bool> {
    if ctx_id == 0 {
        return Ok(false);
    }

    let mut ctx = tool_ctx_map
        .get(&ctx_id, 0)
        .with_context(|| format!("read TOOL_CTX[ctx={ctx_id:#x}] for resolver_error"))?;
    mark_tool_ctx_resolver_error(&mut ctx);
    tool_ctx_map
        .insert(&ctx_id, &ctx, 0)
        .with_context(|| format!("write TOOL_CTX[ctx={ctx_id:#x}] resolver_error"))?;
    Ok(true)
}

fn resolver_failed_event(ev: &ResolverEvent) -> final_state::ResolverProtocolEvent {
    final_state::ResolverProtocolEvent {
        kind: EVENT_RESOLVER_FAILED,
        kind_str: event_kind_str(EVENT_RESOLVER_FAILED).to_string(),
        code_kind: ev.code_kind,
        ctx_id: ev.ctx_id,
        self_ptr: ev.self_ptr,
        type_ptr: ev.type_ptr,
        frame_ptr: ev.frame_ptr,
        code_ptr: ev.code_ptr,
        ts_ns: ev.ts_ns,
        pid: ev.pid,
        tid: ev.tid,
    }
}

fn should_warn_resolver_failure(ev: &ResolverEvent) -> bool {
    ev.ctx_id != 0 || ev.code_kind != CODE_KIND_IGNORE
}

fn event_kind_str(kind: u8) -> &'static str {
    match kind {
        EVENT_TOOL_START => "tool_start",
        EVENT_TOOL_FRAME_END => "tool_frame_end",
        EVENT_TOOL_CONTEXT_END => "tool_context_end",
        EVENT_TASK_BIND => "TASK_BIND",
        EVENT_TASK_UNBIND => "TASK_UNBIND",
        EVENT_WORKER_BIND => "WORKER_BIND",
        EVENT_WORKER_UNBIND => "WORKER_UNBIND",
        EVENT_WORKER_CARRIER_BIND => "WORKER_CARRIER_BIND",
        EVENT_WORKER_CARRIER_UNBIND => "WORKER_CARRIER_UNBIND",
        EVENT_CHILD_CTX_BIND => "CHILD_CTX_BIND",
        EVENT_CHILD_CTX_UNBIND => "CHILD_CTX_UNBIND",
        EVENT_AUDIT_UNATTRIBUTED => "AUDIT_UNATTRIBUTED",
        EVENT_AUDIT_UNRESOLVED => "AUDIT_UNRESOLVED",
        EVENT_AUDIT_STACK_OVERFLOW => "AUDIT_STACK_OVERFLOW",
        EVENT_AUDIT_BUILD_MISMATCH => "AUDIT_BUILD_MISMATCH",
        EVENT_DEALLOC_CLEANUP => "DEALLOC_CLEANUP",
        EVENT_RESOLVER_CANDIDATE => "RESOLVER_CANDIDATE",
        EVENT_RESOLVER_RESOLVED => "RESOLVER_RESOLVED",
        EVENT_RESOLVER_FAILED => "RESOLVER_FAILED",
        _ => "UNKNOWN",
    }
}

fn guard_event_kind_str(kind: u8) -> &'static str {
    match kind {
        EVENT_FS_OPEN => "FILE_OPEN",
        EVENT_EXEC => "EXEC",
        EVENT_NET_CONNECT => "CONNECT",
        EVENT_FORK => "FORK",
        EVENT_EXIT => "EXIT",
        _ => "UNKNOWN",
    }
}

fn identity_state_str(identity_state: u8) -> &'static str {
    match identity_state {
        IDENTITY_STATE_KNOWN_TOOL => "known_tool",
        IDENTITY_STATE_UNKNOWN_TOOL => "unknown_tool",
        IDENTITY_STATE_RESOLVER_ERROR => "resolver_error",
        IDENTITY_STATE_UNATTRIBUTED => "unattributed",
        _ => "invalid",
    }
}

fn policy_source_str(policy_source: u8) -> &'static str {
    match policy_source {
        POLICY_SOURCE_DEFAULT_ALLOW => "default_allow",
        POLICY_SOURCE_TOOL => "tool",
        POLICY_SOURCE_UNATTRIBUTED => "unattributed",
        POLICY_SOURCE_UNKNOWN_TOOL => "unknown_tool",
        POLICY_SOURCE_RESOLVER_ERROR => "resolver_error",
        POLICY_SOURCE_MONITOR => "monitor",
        POLICY_SOURCE_DEFAULT_DENY => "default_deny",
        _ => "invalid",
    }
}

fn guard_tool_name(
    tool_id: u32,
    identity_state: u8,
    table: &std::collections::HashMap<u32, String>,
) -> String {
    match identity_state {
        IDENTITY_STATE_KNOWN_TOOL => table
            .get(&tool_id)
            .cloned()
            .unwrap_or_else(|| format!("unknown_{:#x}", tool_id)),
        IDENTITY_STATE_UNKNOWN_TOOL => "unknown".to_string(),
        IDENTITY_STATE_RESOLVER_ERROR => "resolver_error".to_string(),
        IDENTITY_STATE_UNATTRIBUTED => "unattributed".to_string(),
        _ => "invalid_identity".to_string(),
    }
}

fn extract_guard_path(event: &GuardEvent) -> String {
    let len = (event.path_len as usize).min(MAX_EVENT_PATH_LEN);
    let slice = &event.path[..len];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(len);
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn format_guard_ipv4(addr: u32) -> String {
    Ipv4Addr::from(addr.to_be()).to_string()
}

async fn run_cpython_runtime(args: &Args) -> Result<()> {
    use aya::maps::Array;
    use aya::maps::HashMap as AyaHashMapRef;
    use std::collections::HashMap;

    info!("CPython tool runtime starting");

    let config_path = args
        .config
        .as_ref()
        .context("CPython runtime requires --config <policy.yaml> with at least one agent pid")?;
    let yaml_config = IronScopeYamlConfig::load(config_path)
        .with_context(|| format!("failed to load config: {}", config_path.display()))?;
    let mut runtime_config = yaml_config.ironscope;
    if let Some(ref mode) = args.mode {
        runtime_config.mode = mode.clone();
    }
    let target_pids = configured_agent_pids(&runtime_config)?;
    let primary_pid = target_pids[0];

    let contract_dir = resolve_contract_dir(&args.contract_dir)?;
    let resolved_contract = python_symbols::load_contract_for_pid(&contract_dir, primary_pid)?;
    for pid in target_pids.iter().skip(1) {
        let other = python_symbols::load_contract_for_pid(&contract_dir, *pid)?;
        if other.detected.python_path != resolved_contract.detected.python_path
            || other.detected.asyncio_path != resolved_contract.detected.asyncio_path
            || other.detected.python_build_id != resolved_contract.detected.python_build_id
            || other.detected.asyncio_build_id != resolved_contract.detected.asyncio_build_id
            || other.detected.arch != resolved_contract.detected.arch
        {
            bail!(
                "v0.1 CPython runtime requires all configured agent PIDs to use the same Python executable, _asyncio module, build ids, and architecture; pid {} differs from pid {}",
                pid,
                primary_pid
            );
        }
        info!(
            "validated additional CPython agent pid={} against primary pid={} runtime contract",
            pid, primary_pid
        );
    }
    let contract = resolved_contract.contract;
    info!(
        "loaded CPython contract for primary pid={} agent_pids={} python_build_id={} asyncio_build_id={} arch={} from {}",
        primary_pid,
        target_pids.len(),
        resolved_contract.detected.python_build_id,
        resolved_contract.detected.asyncio_build_id,
        resolved_contract.detected.arch,
        contract_dir.display()
    );

    let rules_path = resolve_framework_rules(&args.framework_rules)?;
    let root_rules = rules::load_rules(&rules_path)
        .with_context(|| format!("failed to load rules: {}", rules_path.display()))?;
    info!(
        "loaded {} root rules from {}",
        root_rules.len(),
        rules_path.display()
    );

    #[repr(C, align(8))]
    struct Aligned<T: ?Sized>(T);
    static EBPF_OBJ: &Aligned<[u8]> =
        &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/ironscope")));
    let mut ebpf = Ebpf::load(&EBPF_OBJ.0)?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to init eBPF logger: {}", e);
    }

    // Populate PYTHON_OFFSETS
    {
        let mut offsets: Array<&mut MapData, u32> = Array::try_from(
            ebpf.map_mut("PYTHON_OFFSETS")
                .context("PYTHON_OFFSETS not found")?,
        )?;
        let frame = &contract.offsets.interp_frame;
        let code = &contract.offsets.code_object;
        let unicode = &contract.offsets.unicode_object;
        let task = &contract.offsets.task_obj;

        offsets.set(0, &(frame.f_executable as u32), 0)?;
        offsets.set(1, &(code.co_qualname as u32), 0)?;
        offsets.set(2, &(code.co_filename as u32), 0)?;
        offsets.set(3, &(unicode.compact_data as u32), 0)?;
        offsets.set(4, &(code.co_firstlineno as u32), 0)?;
        offsets.set(5, &(frame.localsplus as u32), 0)?;
        offsets.set(6, &(frame.previous as u32), 0)?;
        offsets.set(7, &(frame.owner as u32), 0)?;
        offsets.set(8, &(task.task_state as u32), 0)?;
        offsets.set(9, &(task.task_coro as u32), 0)?;
        let frame_reg = contract
            .symbols
            .get("_PyEval_EvalFrameDefault")
            .and_then(|s| s.frame_reg_idx)
            .context("contract missing frame_reg_idx")?;
        offsets.set(10, &(frame_reg as u32), 0)?;
        offsets.set(11, &(code.co_flags as u32), 0)?;
        offsets.set(12, &(contract.offsets.gen_object.gi_iframe as u32), 0)?;
        offsets.set(13, &(contract.offsets.thread_state.current_frame as u32), 0)?;
        offsets.set(14, &(contract.offsets.py_object.ob_type as u32), 0)?;
        offsets.set(15, &(contract.offsets.gen_object.gi_frame_state as u32), 0)?;
        let exception_frame_reg = contract
            .symbols
            .get("_PyEval_EvalFrameDefault")
            .and_then(|s| s.end_exception_frame_reg_idx)
            .context("contract missing end_exception_frame_reg_idx")?;
        offsets.set(16, &(exception_frame_reg as u32), 0)?;
        info!("populated PYTHON_OFFSETS");
    }

    // Populate ROOT_RULES
    {
        let mut rules_map: Array<&mut MapData, RootRule> =
            Array::try_from(ebpf.map_mut("ROOT_RULES").context("ROOT_RULES not found")?)?;
        for (i, rule) in root_rules.iter().enumerate() {
            rules_map.set(i as u32, rule, 0)?;
        }
    }

    // Attach BTF tracepoints
    let btf = Btf::from_sys_fs()?;
    attach_tracepoints(&mut ebpf, &btf)?;

    // Attach LSM hooks or fall back to fentry monitoring
    let lsm_effective = match attach_lsm_hooks(&mut ebpf, &btf) {
        Ok(()) => {
            let active = std::fs::read_to_string("/sys/kernel/security/lsm")
                .map(|s| s.contains("bpf"))
                .unwrap_or(true);
            if active {
                info!("LSM hooks attached and active");
            } else {
                warn!("LSM hooks attached but BPF LSM not in active list");
            }
            active
        }
        Err(e) => {
            warn!("LSM hooks not available: {}", e);
            false
        }
    };

    if !lsm_effective {
        info!("falling back to fentry monitoring probes on security_* functions");
        match attach_fentry_probes(&mut ebpf, &btf) {
            Ok(()) => info!("fentry monitoring probes attached"),
            Err(e) => warn!("fentry probes not available: {}", e),
        }
    }

    let compiled = PolicyCompiler::compile_with_hashed_tool_ids(&runtime_config)?;
    populate_maps(&mut ebpf, &compiled)?;
    info!(
        "loaded enforcement config with {} hashed tool ids",
        compiled.tool_name_to_id.len()
    );

    // Attach frame probes
    let python_binary = &contract.libpython.path;
    let eval_frame_sym = contract
        .symbols
        .get("_PyEval_EvalFrameDefault")
        .context("_PyEval_EvalFrameDefault symbol not in contract")?;
    let start_frame_offset = eval_frame_sym
        .start_frame_file_offset
        .context("contract missing start_frame_file_offset")?;
    let frame_reg_idx = eval_frame_sym
        .frame_reg_idx
        .context("contract missing frame_reg_idx")?;
    let resume_offset = eval_frame_sym
        .resume_file_offset
        .context("contract missing resume_file_offset")?;

    let prog: &mut UProbe = ebpf.program_mut("eval_frame_entry").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, start_frame_offset, python_binary, None)?;
    let mut start_frame_probe_count = 1usize;
    for extra_offset in &eval_frame_sym.start_frame_extra_file_offsets {
        if *extra_offset == start_frame_offset || *extra_offset == resume_offset {
            continue;
        }
        prog.attach(None, *extra_offset, python_binary, None)?;
        start_frame_probe_count += 1;
        info!(
            "attached extra start_frame uprobe at offset {:#x} (frame in x{})",
            extra_offset, frame_reg_idx
        );
    }
    info!(
        "attached {} start_frame uprobe(s), primary offset {:#x} (frame in x{})",
        start_frame_probe_count, start_frame_offset, frame_reg_idx
    );

    let worker_prog: &mut UProbe = ebpf
        .program_mut("worker_eval_frame_entry")
        .unwrap()
        .try_into()?;
    worker_prog.load()?;
    worker_prog.attach(None, start_frame_offset, python_binary, None)?;
    let mut worker_start_probe_count = 1usize;
    for extra_offset in &eval_frame_sym.start_frame_extra_file_offsets {
        if *extra_offset == start_frame_offset || *extra_offset == resume_offset {
            continue;
        }
        worker_prog.attach(None, *extra_offset, python_binary, None)?;
        worker_start_probe_count += 1;
    }
    info!(
        "attached {} worker start_frame uprobe(s)",
        worker_start_probe_count
    );

    let end_rv_offset = eval_frame_sym
        .end_return_value_file_offset
        .context("contract missing end_return_value_file_offset")?;
    let end_rc_offset = eval_frame_sym
        .end_return_const_file_offset
        .context("contract missing end_return_const_file_offset")?;
    let end_exc_offset = eval_frame_sym
        .end_exception_file_offset
        .context("contract missing end_exception_file_offset")?;

    let prog: &mut UProbe = ebpf.program_mut("eval_frame_end_rv").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, end_rv_offset, python_binary, None)?;

    let mut end_probe_count = 1;
    if end_rc_offset != end_rv_offset {
        let prog: &mut UProbe = ebpf.program_mut("eval_frame_end_rc").unwrap().try_into()?;
        prog.load()?;
        prog.attach(None, end_rc_offset, python_binary, None)?;
        end_probe_count += 1;
    } else {
        info!(
            "skipping duplicate RETURN_CONST end probe at offset {:#x}",
            end_rc_offset
        );
    }

    if end_exc_offset != end_rv_offset && end_exc_offset != end_rc_offset {
        let prog: &mut UProbe = ebpf.program_mut("eval_frame_end_exc").unwrap().try_into()?;
        prog.load()?;
        prog.attach(None, end_exc_offset, python_binary, None)?;
        end_probe_count += 1;
    } else {
        info!(
            "skipping duplicate exception end probe at offset {:#x}",
            end_exc_offset
        );
    }
    info!("attached {} end probes", end_probe_count);

    // Companion function-entry probe — required for reliable detection
    // across all CPython 3.12 CALL specialization variants.
    let prog: &mut UProbe = ebpf
        .program_mut("eval_frame_func_entry")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(None, eval_frame_sym.file_offset, python_binary, None)?;
    info!(
        "attached function-entry companion probe at offset {:#x}",
        eval_frame_sym.file_offset
    );

    let prog: &mut UProbe = ebpf
        .program_mut("worker_eval_frame_func_entry")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(None, eval_frame_sym.file_offset, python_binary, None)?;
    info!("attached worker function-entry companion probe");

    // RESUME bytecode handler probe. Catches every coroutine/generator resume,
    // including async tool executions where the start_frame interior probe can
    // miss a later body resume. The attach offset is contract-defined.
    let prog: &mut UProbe = ebpf.program_mut("eval_resume").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, resume_offset, python_binary, None)?;
    info!("attached RESUME bytecode handler probe");

    let prog: &mut UProbe = ebpf.program_mut("worker_eval_resume").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, resume_offset, python_binary, None)?;
    info!("attached worker RESUME bytecode handler probe");

    // Attach task probes
    let asyncio_binary = &contract.asyncio_module.path;

    let task_init_offset = contract.symbol_offset("_asyncio_Task___init___impl")?;
    let prog: &mut UProbe = ebpf.program_mut("asyncio_task_init").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, task_init_offset, asyncio_binary, None)?;

    let task_step_offset = contract.symbol_offset("task_step")?;
    let prog: &mut UProbe = ebpf.program_mut("asyncio_task_step").unwrap().try_into()?;
    prog.load()?;
    prog.attach(None, task_step_offset, asyncio_binary, None)?;

    let prog: &mut UProbe = ebpf
        .program_mut("asyncio_task_step_ret")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(None, task_step_offset, asyncio_binary, None)?;

    let task_eager_offset = contract.symbol_offset("task_eager_start")?;
    let prog: &mut UProbe = ebpf
        .program_mut("asyncio_task_eager_start")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(None, task_eager_offset, asyncio_binary, None)?;

    let prog: &mut UProbe = ebpf
        .program_mut("asyncio_task_eager_start_ret")
        .unwrap()
        .try_into()?;
    prog.load()?;
    prog.attach(None, task_eager_offset, asyncio_binary, None)?;
    info!("attached task probes");

    // Attach dealloc backstop probes for generator, coroutine, and async-generator objects.
    let prog: &mut UProbe = ebpf.program_mut("gen_dealloc").unwrap().try_into()?;
    prog.load()?;
    let mut attached_dealloc_offsets: Vec<(PathBuf, u64)> = Vec::new();
    for dealloc_sym in [
        "PyGen_Type_tp_dealloc",
        "PyCoro_Type_tp_dealloc",
        "PyAsyncGen_Type_tp_dealloc",
    ] {
        let dealloc_offset = contract.symbol_offset(dealloc_sym)?;
        let dealloc_binary = contract.symbol_binary(dealloc_sym)?;
        let attach_key = (dealloc_binary.to_path_buf(), dealloc_offset);
        if attached_dealloc_offsets
            .iter()
            .any(|seen| *seen == attach_key)
        {
            info!(
                "skipping duplicate {} uprobe at offset {:#x}",
                dealloc_sym, dealloc_offset
            );
            continue;
        }
        prog.attach(None, dealloc_offset, dealloc_binary, None)?;
        attached_dealloc_offsets.push(attach_key);
        info!(
            "attached {} uprobe at offset {:#x}",
            dealloc_sym, dealloc_offset
        );
    }

    let prog: &mut UProbe = ebpf.program_mut("gen_dealloc").unwrap().try_into()?;
    prog.attach(Some("PyObject_Free"), 0, python_binary, None)
        .context("failed to attach PyObject_Free dealloc probe")?;
    info!("attached PyObject_Free dealloc uprobe");

    let prog: &mut UProbe = ebpf.program_mut("gen_dealloc").unwrap().try_into()?;
    prog.attach(Some("PyObject_GC_Del"), 0, python_binary, None)
        .context("failed to attach PyObject_GC_Del dealloc probe")?;
    info!("attached PyObject_GC_Del dealloc uprobe");

    // Take TOOL_OBJ map so userspace can publish dynamically resolved runtime tool identities.
    let tool_obj_data = ebpf.take_map("TOOL_OBJ").context("TOOL_OBJ not found")?;
    let mut tool_obj_map: AyaHashMap<MapData, PyObjectKey, ToolObjCacheEntry> =
        AyaHashMap::try_from(tool_obj_data)?;

    // Take TOOL_CTX so userspace can resolve an in-flight unknown context after
    // receiving a resolver candidate. Final-state counting uses this handle too.
    let tool_ctx_data = ebpf.take_map("TOOL_CTX").context("TOOL_CTX not found")?;
    let mut tool_ctx_map: AyaHashMap<MapData, u64, ToolCtx> = AyaHashMap::try_from(tool_ctx_data)?;

    let mut py_ring: RingBuf<MapData> = RingBuf::try_from(
        ebpf.take_map("PY_EVENTS")
            .context("PY_EVENTS map not found")?,
    )?;

    let mut resolver_ring: RingBuf<MapData> = RingBuf::try_from(
        ebpf.take_map("RESOLVER_EVENTS")
            .context("RESOLVER_EVENTS map not found")?,
    )?;

    let mut guard_ring: RingBuf<MapData> = RingBuf::try_from(
        ebpf.take_map("GUARD_EVENTS")
            .context("GUARD_EVENTS map not found")?,
    )?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx_clone.send(true);
    });

    let shutdown_tx_term = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM");
        sig.recv().await;
        let _ = shutdown_tx_term.send(true);
    });

    let mut py_events: Vec<final_state::RuntimePyEvent> = Vec::new();
    let mut resolver_events: Vec<final_state::ResolverProtocolEvent> = Vec::new();
    let mut guard_events: Vec<final_state::GuardAuditEvent> = Vec::new();
    let mut tool_name_table: HashMap<u32, String> = HashMap::new();
    let mut runtime_resolvers: HashMap<u32, python_runtime::cpython::LiveCpythonResolver> =
        HashMap::new();
    let mut ready_written = false;
    let ready_path = args.ready_file.clone();
    let start = std::time::Instant::now();
    let max_duration = (args.duration > 0).then(|| Duration::from_secs(args.duration));

    let _ = std::fs::remove_file(&ready_path);

    if let Some(parent) = ready_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    if let Some(max_duration) = max_duration {
        info!(
            "CPython runtime event loop running (max {}s)...",
            max_duration.as_secs()
        );
    } else {
        info!("CPython runtime event loop running until stopped...");
    }

    loop {
        if *shutdown_rx.borrow() || max_duration.map_or(false, |d| start.elapsed() >= d) {
            break;
        }

        if !ready_written {
            std::fs::write(&ready_path, b"1").ok();
            ready_written = true;
            info!("runtime ready marker written {}", ready_path.display());
        }

        while let Some(item) = py_ring.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<PyEvent>() {
                continue;
            }
            let ev: &PyEvent = unsafe { &*(data.as_ptr() as *const PyEvent) };
            let kind_str = event_kind_str(ev.kind);
            info!(
                "py_event: kind={} ({}) ctx={:#x} tool={:#x} carrier={:#x} aux={} pid={} tid={}",
                ev.kind, kind_str, ev.ctx_id, ev.tool_id, ev.carrier_ptr, ev.aux, ev.pid, ev.tid
            );
            py_events.push(final_state::RuntimePyEvent {
                kind: ev.kind,
                kind_str: kind_str.to_string(),
                ctx_id: ev.ctx_id,
                tool_id: ev.tool_id,
                pid: ev.pid,
                tid: ev.tid,
                ts_ns: ev.ts_ns,
                carrier_ptr: ev.carrier_ptr,
                aux: ev.aux,
            });
        }

        while let Some(item) = resolver_ring.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<ResolverEvent>() {
                continue;
            }
            let ev: &ResolverEvent = unsafe { &*(data.as_ptr() as *const ResolverEvent) };
            let kind_str = event_kind_str(ev.kind);
            info!(
                "resolver_event: kind={} ({}) code_kind={} ctx={:#x} self={:#x} type={:#x} frame={:#x} code={:#x} pid={} tid={}",
                ev.kind,
                kind_str,
                ev.code_kind,
                ev.ctx_id,
                ev.self_ptr,
                ev.type_ptr,
                ev.frame_ptr,
                ev.code_ptr,
                ev.pid,
                ev.tid
            );

            resolver_events.push(final_state::ResolverProtocolEvent {
                kind: ev.kind,
                kind_str: kind_str.to_string(),
                code_kind: ev.code_kind,
                ctx_id: ev.ctx_id,
                self_ptr: ev.self_ptr,
                type_ptr: ev.type_ptr,
                frame_ptr: ev.frame_ptr,
                code_ptr: ev.code_ptr,
                ts_ns: ev.ts_ns,
                pid: ev.pid,
                tid: ev.tid,
            });

            if ev.kind == EVENT_RESOLVER_CANDIDATE {
                if !runtime_resolvers.contains_key(&ev.pid) {
                    match python_runtime::cpython::LiveCpythonResolver::detect_for_pid(ev.pid) {
                        Ok((resolver, detected)) => {
                            info!(
                                "resolver attached to pid={} python={}.{}.{} pointer_width={}",
                                ev.pid,
                                detected.version.major,
                                detected.version.minor,
                                detected.version.micro,
                                detected.pointer_width
                            );
                            runtime_resolvers.insert(ev.pid, resolver);
                        }
                        Err(err) => {
                            warn!(
                                "failed to initialize CPython resolver for pid {}: {}",
                                ev.pid, err
                            );
                            match mark_tool_ctx_map_resolver_error(&mut tool_ctx_map, ev.ctx_id) {
                                Ok(true) => {
                                    resolver_events.push(resolver_failed_event(ev));
                                    warn!(
                                        "marked TOOL_CTX[ctx={:#x}] resolver_error after resolver init failure",
                                        ev.ctx_id
                                    );
                                }
                                Ok(false) => {}
                                Err(update_err) => warn!(
                                    "failed to mark TOOL_CTX[ctx={:#x}] resolver_error after resolver init failure: {}",
                                    ev.ctx_id, update_err
                                ),
                            }
                        }
                    }
                }

                if let Some(cpython) = runtime_resolvers.get(&ev.pid) {
                    let langchain = python_runtime::langchain::LangChainResolver::new(cpython);
                    let resolved_result =
                        if ev.code_kind == CODE_KIND_IGNORE {
                            langchain.resolve_tool(ev.self_ptr)
                        } else {
                            langchain.classify_code(ev.code_ptr).and_then(|kind| match kind {
                            python_runtime::langchain::LangChainCodeKind::ToolBoundary => {
                                langchain.resolve_tool(ev.self_ptr)
                            }
                            python_runtime::langchain::LangChainCodeKind::Other => {
                                bail!("resolver candidate code is not a LangChain tool boundary")
                            }
                        })
                        };
                    match resolved_result {
                        Ok(resolved) => {
                            let key = PyObjectKey {
                                tgid: ev.pid,
                                _pad: 0,
                                ptr: ev.self_ptr,
                            };
                            let cache_entry = ToolObjCacheEntry {
                                type_ptr: ev.type_ptr,
                                tool_id: resolved.tool_id,
                                name_hash: resolved.tool_id,
                                generation: 0,
                                _pad: 0,
                            };
                            if let Err(err) = tool_obj_map.insert(&key, &cache_entry, 0) {
                                warn!(
                                    "failed to insert resolved TOOL_OBJ[pid={} ptr={:#x} type={:#x}]: {}",
                                    ev.pid, ev.self_ptr, ev.type_ptr, err
                                );
                            } else {
                                info!(
                                    "resolver cached TOOL_OBJ[pid={} ptr={:#x} type={:#x}] = {:#x} ({})",
                                    ev.pid, ev.self_ptr, ev.type_ptr, resolved.tool_id, resolved.name
                                );
                            }

                            if ev.ctx_id != 0 {
                                match tool_ctx_map.get(&ev.ctx_id, 0) {
                                    Ok(mut active_ctx) => {
                                        active_ctx.tool_id = resolved.tool_id;
                                        active_ctx.flags |= TOOL_CTX_FLAG_RESOLVED;
                                        active_ctx.generation =
                                            active_ctx.generation.wrapping_add(1);
                                        if let Err(err) =
                                            tool_ctx_map.insert(&ev.ctx_id, &active_ctx, 0)
                                        {
                                            warn!(
                                                "failed to update resolved TOOL_CTX[ctx={:#x}] = {:#x}: {}",
                                                ev.ctx_id, resolved.tool_id, err
                                            );
                                        } else {
                                            for prior in py_events.iter_mut() {
                                                if prior.ctx_id == ev.ctx_id
                                                    && prior.tool_id == TOOL_IDLE
                                                {
                                                    prior.tool_id = resolved.tool_id;
                                                }
                                            }
                                            info!(
                                                "resolver updated TOOL_CTX[ctx={:#x}] = {:#x} ({})",
                                                ev.ctx_id, resolved.tool_id, resolved.name
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            "failed to read TOOL_CTX[ctx={:#x}] for resolved tool {:#x}: {}",
                                            ev.ctx_id, resolved.tool_id, err
                                        );
                                    }
                                }
                            }

                            tool_name_table.insert(resolved.tool_id, resolved.name);
                        }
                        Err(err) => {
                            if should_warn_resolver_failure(ev) {
                                warn!(
                                    "failed to resolve LangChain tool candidate pid={} ctx={:#x} self={:#x}: {}",
                                    ev.pid, ev.ctx_id, ev.self_ptr, err
                                );
                            } else {
                                debug!(
                                    "ignored speculative LangChain resolver candidate pid={} self={:#x}: {}",
                                    ev.pid, ev.self_ptr, err
                                );
                            }
                            match mark_tool_ctx_map_resolver_error(&mut tool_ctx_map, ev.ctx_id) {
                                Ok(true) => {
                                    resolver_events.push(resolver_failed_event(ev));
                                    warn!(
                                        "marked TOOL_CTX[ctx={:#x}] resolver_error after userspace resolution failure",
                                        ev.ctx_id
                                    );
                                }
                                Ok(false) => {}
                                Err(update_err) => warn!(
                                    "failed to mark TOOL_CTX[ctx={:#x}] resolver_error after userspace resolution failure: {}",
                                    ev.ctx_id, update_err
                                ),
                            }
                        }
                    }
                }
            }
        }

        while let Some(item) = guard_ring.next() {
            let data = item.as_ref();
            if data.len() < std::mem::size_of::<GuardEvent>() {
                continue;
            }
            let ev: &GuardEvent = unsafe { &*(data.as_ptr() as *const GuardEvent) };
            let kind_str = guard_event_kind_str(ev.kind);
            let identity_state = identity_state_str(ev.identity_state);
            let policy_source = policy_source_str(ev.policy_source);
            let tool_name = guard_tool_name(ev.tool_id, ev.identity_state, &tool_name_table);
            let path = extract_guard_path(ev);
            let (addr, port) = if ev.kind == EVENT_NET_CONNECT {
                (
                    Some(format_guard_ipv4(ev.addr)),
                    Some(u16::from_be(ev.port)),
                )
            } else {
                (None, None)
            };
            let action_str = if ev.action == ACTION_DENY {
                "deny"
            } else {
                "allow"
            };

            info!("guard_event: kind={} ({}) ctx={:#x} tool={:#x} ({}) identity={} policy_source={} path={} addr={:?} port={:?} action={} pid={} tid={}",
                ev.kind, kind_str, ev.ctx_id, ev.tool_id, tool_name, identity_state, policy_source, path, addr, port, action_str, ev.pid, ev.tid);

            guard_events.push(final_state::GuardAuditEvent {
                kind: ev.kind,
                kind_str: kind_str.to_string(),
                ctx_id: ev.ctx_id,
                tool_id: ev.tool_id,
                tool_name,
                identity_state: identity_state.to_string(),
                policy_source: policy_source.to_string(),
                path,
                addr,
                port,
                action: action_str.to_string(),
                ts_ns: ev.ts_ns,
                pid: ev.pid,
                tid: ev.tid,
            });
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Analyze py_events
    let start_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_TOOL_START)
        .count();
    let end_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_TOOL_END)
        .count();
    let balanced = start_count == end_count;
    let orphan_frame_ctx = start_count.saturating_sub(end_count) as u32;

    let task_bind_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_TASK_BIND)
        .count() as u32;
    let task_unbind_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_TASK_UNBIND)
        .count() as u32;
    let worker_bind_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_WORKER_BIND)
        .count() as u32;
    let worker_unbind_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_WORKER_UNBIND)
        .count() as u32;
    let stack_overflow_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_AUDIT_STACK_OVERFLOW)
        .count() as u32;
    let dealloc_cleanup_count = py_events
        .iter()
        .filter(|e| e.kind == EVENT_DEALLOC_CLEANUP)
        .count() as u32;
    let audit_unresolved = py_events
        .iter()
        .filter(|e| e.kind == EVENT_AUDIT_UNRESOLVED)
        .count() as u32;
    let audit_unattributed = py_events
        .iter()
        .filter(|e| e.kind == EVENT_AUDIT_UNATTRIBUTED)
        .count() as u32;

    let mut tool_dispatches: HashMap<String, final_state::ToolDispatchInfo> = HashMap::new();
    for e in py_events
        .iter()
        .filter(|e| e.kind == EVENT_TOOL_END && e.tool_id != 0)
    {
        let key = format!("{:#x}", e.tool_id);
        let entry = tool_dispatches.entry(key).or_insert_with(|| {
            let name = tool_name_table
                .get(&e.tool_id)
                .cloned()
                .unwrap_or_else(|| format!("unknown_{:#x}", e.tool_id));
            final_state::ToolDispatchInfo { name, count: 0 }
        });
        entry.count += 1;
    }

    // Bracket check: for each guard event with a non-zero ctx_id, verify its
    // timestamp falls within a tool_start/tool_context_end bracket for that ctx_id.
    let total_guard = guard_events.len() as u32;
    let attributed_guard = guard_events.iter().filter(|e| e.ctx_id != 0).count() as u32;

    let mut brackets: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    {
        let mut open_starts: HashMap<u64, u64> = HashMap::new();
        for ev in &py_events {
            if ev.kind == EVENT_TOOL_START {
                open_starts.insert(ev.ctx_id, ev.ts_ns);
            } else if ev.kind == EVENT_TOOL_END {
                if let Some(start_ts) = open_starts.remove(&ev.ctx_id) {
                    brackets
                        .entry(ev.ctx_id)
                        .or_default()
                        .push((start_ts, ev.ts_ns));
                }
            }
        }
        for (ctx_id, start_ts) in open_starts {
            brackets
                .entry(ctx_id)
                .or_default()
                .push((start_ts, u64::MAX));
        }
    }

    let mut bracket_violations = 0u32;

    for ge in &guard_events {
        if ge.ctx_id != 0 {
            let in_bracket = brackets.get(&ge.ctx_id).map_or(false, |intervals| {
                intervals
                    .iter()
                    .any(|&(s, e)| ge.ts_ns >= s && ge.ts_ns <= e)
            });
            if !in_bracket {
                bracket_violations += 1;
            }
        }
    }

    // Final state introspection
    let mut leaked_tool_ctx = Vec::new();
    for item in tool_ctx_map.iter().filter_map(|r| r.ok()) {
        let (ctx_id, ctx) = item;
        leaked_tool_ctx.push((ctx_id, ctx.tool_id, ctx.carrier_count, ctx.flags));
    }
    let tool_ctx_count = leaked_tool_ctx.len() as u32;
    if tool_ctx_count != 0 {
        warn!("final TOOL_CTX entries still live: {:?}", leaked_tool_ctx);
    }

    let task_ctx_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u64> =
            aya::maps::HashMap::try_from(ebpf.map("TASK_CTX").context("TASK_CTX not found")?)?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let task_ctx_stack_count = {
        let map: AyaHashMapRef<&MapData, TaskStackKey, u64> = AyaHashMapRef::try_from(
            ebpf.map("TASK_CTX_STACK")
                .context("TASK_CTX_STACK not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let task_ctx_depth_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u32> = aya::maps::HashMap::try_from(
            ebpf.map("TASK_CTX_DEPTH")
                .context("TASK_CTX_DEPTH not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let pending_tool_close_count = {
        let map: AyaHashMapRef<&MapData, TaskStackKey, ToolStackEntry> = AyaHashMapRef::try_from(
            ebpf.map("PENDING_TOOL_CLOSE")
                .context("PENDING_TOOL_CLOSE not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let pending_frame_tool_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u32> = aya::maps::HashMap::try_from(
            ebpf.map("PENDING_FRAME_TOOL")
                .context("PENDING_FRAME_TOOL not found")?,
        )?;
        let mut pending = Vec::new();
        for item in map.iter().filter_map(|r| r.ok()) {
            let (key, tool_id) = item;
            pending.push((key.tgid, key.ptr, tool_id));
        }
        if !pending.is_empty() {
            warn!("final PENDING_FRAME_TOOL entries still live: {:?}", pending);
        }
        pending.len() as u32
    };

    let fork_ctx_count = {
        let map: aya::maps::HashMap<&MapData, u32, u64> =
            aya::maps::HashMap::try_from(ebpf.map("FORK_CTX").context("FORK_CTX not found")?)?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let workitem_ctx_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u64> = aya::maps::HashMap::try_from(
            ebpf.map("WORKITEM_CTX").context("WORKITEM_CTX not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let pythread_obj_ctx_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u64> = aya::maps::HashMap::try_from(
            ebpf.map("PYTHREAD_OBJ_CTX")
                .context("PYTHREAD_OBJ_CTX not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let pythread_obj_thread_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u32> = aya::maps::HashMap::try_from(
            ebpf.map("PYTHREAD_OBJ_THREAD")
                .context("PYTHREAD_OBJ_THREAD not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let frame_ctx_count = {
        let map: aya::maps::HashMap<&MapData, PyObjectKey, u64> =
            aya::maps::HashMap::try_from(ebpf.map("FRAME_CTX").context("FRAME_CTX not found")?)?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_active_ctx_count = {
        let map: AyaHashMapRef<&MapData, u32, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_ACTIVE_CTX")
                .context("THREAD_ACTIVE_CTX not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_active_task_count = {
        let map: AyaHashMapRef<&MapData, u32, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_ACTIVE_TASK")
                .context("THREAD_ACTIVE_TASK not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_ctx_stack_count = {
        let map: AyaHashMapRef<&MapData, u64, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_CTX_STACK")
                .context("THREAD_CTX_STACK not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_ctx_depth_count = {
        let map: AyaHashMapRef<&MapData, u32, u8> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_CTX_DEPTH")
                .context("THREAD_CTX_DEPTH not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let threadpool_worker_frame_count = {
        let map: AyaHashMapRef<&MapData, u32, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREADPOOL_WORKER_FRAME")
                .context("THREADPOOL_WORKER_FRAME not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let threadpool_worker_ctx_count = {
        let map: AyaHashMapRef<&MapData, u32, WorkerLocalCtx> = AyaHashMapRef::try_from(
            ebpf.map("THREADPOOL_WORKER_CTX")
                .context("THREADPOOL_WORKER_CTX not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let threadpool_workitem_thread_count = {
        let map: AyaHashMapRef<&MapData, PyObjectKey, u32> = AyaHashMapRef::try_from(
            ebpf.map("THREADPOOL_WORKITEM_THREAD")
                .context("THREADPOOL_WORKITEM_THREAD not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_current_frame_count = {
        let map: AyaHashMapRef<&MapData, u32, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_CURRENT_FRAME")
                .context("THREAD_CURRENT_FRAME not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let thread_tstate_count = {
        let map: AyaHashMapRef<&MapData, u32, u64> = AyaHashMapRef::try_from(
            ebpf.map("THREAD_TSTATE")
                .context("THREAD_TSTATE not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let frame_entry_stash_count = {
        let map: AyaHashMapRef<&MapData, u64, u64> = AyaHashMapRef::try_from(
            ebpf.map("FRAME_ENTRY_STASH")
                .context("FRAME_ENTRY_STASH not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let frame_stash_depth_count = {
        let map: AyaHashMapRef<&MapData, u32, u32> = AyaHashMapRef::try_from(
            ebpf.map("FRAME_STASH_DEPTH")
                .context("FRAME_STASH_DEPTH not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let worker_run_stack_count = {
        let map: AyaHashMapRef<&MapData, u64, WorkerRunEntry> = AyaHashMapRef::try_from(
            ebpf.map("WORKER_RUN_STACK")
                .context("WORKER_RUN_STACK not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let worker_run_carrier_count = {
        let map: AyaHashMapRef<&MapData, PyObjectKey, u32> = AyaHashMapRef::try_from(
            ebpf.map("WORKER_RUN_CARRIER")
                .context("WORKER_RUN_CARRIER not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    let worker_run_active_count = {
        let map: AyaHashMapRef<&MapData, u32, u32> = AyaHashMapRef::try_from(
            ebpf.map("WORKER_RUN_DEPTH")
                .context("WORKER_RUN_DEPTH not found")?,
        )?;
        map.iter().filter(|r| r.is_ok()).count() as u32
    };

    info!(
        "CPython runtime complete: {} py_events ({} starts, {} ends), balanced={}",
        py_events.len(),
        start_count,
        end_count,
        balanced
    );
    info!(
        "  {} guard events ({} attributed), bracket_violations={}",
        total_guard, attributed_guard, bracket_violations
    );
    info!("  audit_unattributed={}", audit_unattributed);
    info!(
        "  task: binds={}, unbinds={}",
        task_bind_count, task_unbind_count
    );
    info!(
        "  worker: binds={}, unbinds={}",
        worker_bind_count, worker_unbind_count
    );
    info!(
        "  lifecycle: stack_overflow={}, dealloc_cleanup={}",
        stack_overflow_count, dealloc_cleanup_count
    );

    if let Some(ref output_path) = args.output {
        let result = final_state::RuntimeAuditReport {
            schema_version: "ironscope.audit.v1",
            runtime: "cpython",
            py_events,
            resolver_events,
            guard_events,
            balanced,
            orphan_frame_ctx,
            tool_dispatches,
            audit_unresolved,
            audit_unattributed,
            task_bind_count,
            task_unbind_count,
            worker_bind_count,
            worker_unbind_count,
            stack_overflow_count,
            dealloc_cleanup_count,
            bracket_check: final_state::BracketCheck {
                total_guard_events: total_guard,
                attributed_guard_events: attributed_guard,
                bracket_violations,
            },
            final_state: final_state::RuntimeFinalState {
                tool_ctx_count,
                task_ctx_count,
                task_ctx_stack_count,
                task_ctx_depth_count,
                pending_tool_close_count,
                pending_frame_tool_count,
                fork_ctx_count,
                workitem_ctx_count,
                pythread_obj_ctx_count,
                pythread_obj_thread_count,
                frame_ctx_count,
                thread_active_ctx_count,
                thread_active_task_count,
                thread_ctx_stack_count,
                thread_ctx_depth_count,
                threadpool_worker_frame_count,
                threadpool_worker_ctx_count,
                threadpool_workitem_thread_count,
                thread_current_frame_count,
                thread_tstate_count,
                frame_entry_stash_count,
                frame_stash_depth_count,
                worker_run_stack_count,
                worker_run_carrier_count,
                worker_run_active_count,
            },
        };
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(output_path, &json)?;
        chown_to_real_user(output_path);
        info!("wrote CPython runtime output to {}", output_path.display());
    }

    let _ = std::fs::remove_file(&ready_path);

    Ok(())
}

#[cfg(test)]
mod resolver_error_state_tests {
    use super::*;
    #[test]
    fn resolver_error_state_clears_resolved_identity_and_preserves_lifecycle_fields() {
        let mut ctx = ToolCtx {
            tool_id: 0xfeed_beef,
            generation: u32::MAX,
            carrier_count: 3,
            flags: TOOL_CTX_FLAG_RESOLVED | TOOL_CTX_FLAG_ASYNC_FRAME,
            started_ns: 11,
            last_seen_ns: 22,
        };

        mark_tool_ctx_resolver_error(&mut ctx);

        assert_eq!(ctx.tool_id, TOOL_IDLE);
        assert_eq!(ctx.generation, 0);
        assert_eq!(ctx.carrier_count, 3);
        assert_eq!(ctx.started_ns, 11);
        assert_eq!(ctx.last_seen_ns, 22);
        assert_eq!(ctx.flags & TOOL_CTX_FLAG_RESOLVED, 0);
        assert_ne!(ctx.flags & TOOL_CTX_FLAG_RESOLVER_ERROR, 0);
        assert_ne!(ctx.flags & TOOL_CTX_FLAG_ASYNC_FRAME, 0);
    }

    #[test]
    fn resolver_failed_event_preserves_candidate_identity() {
        let ev = ResolverEvent {
            kind: EVENT_RESOLVER_CANDIDATE,
            code_kind: CODE_KIND_TOOL_ROOT_LC,
            ctx_id: 0x1234,
            self_ptr: 0x2000,
            type_ptr: 0x3000,
            frame_ptr: 0x4000,
            code_ptr: 0x5000,
            ts_ns: 99,
            pid: 42,
            tid: 43,
            _pad: [0; 2],
        };

        let failed = resolver_failed_event(&ev);

        assert_eq!(failed.kind, EVENT_RESOLVER_FAILED);
        assert_eq!(failed.kind_str, "RESOLVER_FAILED");
        assert_eq!(failed.code_kind, ev.code_kind);
        assert_eq!(failed.ctx_id, ev.ctx_id);
        assert_eq!(failed.self_ptr, ev.self_ptr);
        assert_eq!(failed.type_ptr, ev.type_ptr);
        assert_eq!(failed.frame_ptr, ev.frame_ptr);
        assert_eq!(failed.code_ptr, ev.code_ptr);
        assert_eq!(failed.ts_ns, ev.ts_ns);
        assert_eq!(failed.pid, ev.pid);
        assert_eq!(failed.tid, ev.tid);
    }

    #[test]
    fn resolver_error_state_is_idempotent_except_generation() {
        let mut ctx = ToolCtx {
            tool_id: TOOL_IDLE,
            generation: 7,
            carrier_count: 0,
            flags: TOOL_CTX_FLAG_RESOLVER_ERROR,
            started_ns: 0,
            last_seen_ns: 0,
        };

        mark_tool_ctx_resolver_error(&mut ctx);

        assert_eq!(ctx.tool_id, TOOL_IDLE);
        assert_eq!(ctx.generation, 8);
        assert_eq!(ctx.flags, TOOL_CTX_FLAG_RESOLVER_ERROR);
    }

    #[test]
    fn speculative_ignore_candidates_do_not_emit_resolver_warning() {
        let speculative = ResolverEvent {
            kind: EVENT_RESOLVER_CANDIDATE,
            code_kind: CODE_KIND_IGNORE,
            ctx_id: 0,
            self_ptr: 0x2000,
            type_ptr: 0x3000,
            frame_ptr: 0x4000,
            code_ptr: 0x5000,
            ts_ns: 99,
            pid: 42,
            tid: 43,
            _pad: [0; 2],
        };
        let active_context_candidate = ResolverEvent {
            ctx_id: 0x1234,
            ..speculative
        };
        let proven_tool_boundary = ResolverEvent {
            code_kind: CODE_KIND_TOOL_ROOT_LC,
            ..speculative
        };

        assert!(!should_warn_resolver_failure(&speculative));
        assert!(should_warn_resolver_failure(&active_context_candidate));
        assert!(should_warn_resolver_failure(&proven_tool_boundary));
    }
}
