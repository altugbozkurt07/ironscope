#![cfg_attr(target_arch = "bpf", no_std)]
#![no_main]

#[cfg(target_arch = "bpf")]
mod alloc;
#[cfg(target_arch = "bpf")]
mod code_classifier;
#[cfg(target_arch = "bpf")]
mod event_emit;
#[cfg(target_arch = "bpf")]
mod fork_probes;
#[cfg(target_arch = "bpf")]
mod frame_probes;
#[cfg(target_arch = "bpf")]
mod lifecycle;
#[cfg(target_arch = "bpf")]
mod lsm_hooks;
#[cfg(target_arch = "bpf")]
mod maps;
#[cfg(target_arch = "bpf")]
mod ownership;
#[cfg(target_arch = "bpf")]
mod task_probes;
#[cfg(target_arch = "bpf")]
mod tool_identity;
#[cfg(target_arch = "bpf")]
mod worker_probes;

#[cfg(target_arch = "bpf")]
mod programs {
    use aya_ebpf::macros::{btf_tracepoint, fentry, lsm, uprobe, uretprobe};
    use aya_ebpf::programs::{
        BtfTracePointContext, FEntryContext, LsmContext, ProbeContext, RetProbeContext,
    };

    #[btf_tracepoint(function = "sched_process_fork")]
    pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
        crate::fork_probes::handle_sched_fork(&ctx).unwrap_or(0)
    }

    #[btf_tracepoint(function = "sched_process_exit")]
    pub fn sched_process_exit(ctx: BtfTracePointContext) -> u32 {
        crate::fork_probes::handle_sched_exit(&ctx).unwrap_or(0)
    }

    #[btf_tracepoint(function = "sched_process_exec")]
    pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
        crate::fork_probes::handle_sched_exec(&ctx).unwrap_or(0)
    }

    #[uprobe]
    pub fn eval_frame_entry(ctx: ProbeContext) -> u32 {
        crate::frame_probes::handle_frame_entry(&ctx).unwrap_or(());
        0
    }

    // Function-entry companion for _PyEval_EvalFrameDefault.
    #[uprobe]
    pub fn eval_frame_func_entry(ctx: ProbeContext) -> u32 {
        crate::frame_probes::handle_frame_func_entry(&ctx).unwrap_or(());
        0
    }

    // RESUME bytecode handler probe. Fires on every coroutine/generator
    // RESUME, including body resumes that the start_frame interior probe
    // misses. The attach offset is loaded from the target CPython contract.
    #[uprobe]
    pub fn eval_resume(ctx: ProbeContext) -> u32 {
        let _ = crate::frame_probes::handle_frame_resume(&ctx);
        0
    }

    #[uprobe]
    pub fn worker_eval_frame_entry(ctx: ProbeContext) -> u32 {
        crate::worker_probes::handle_frame_entry(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn worker_eval_frame_func_entry(ctx: ProbeContext) -> u32 {
        crate::worker_probes::handle_frame_func_entry(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn worker_eval_resume(ctx: ProbeContext) -> u32 {
        crate::worker_probes::handle_frame_resume(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn eval_frame_end_rv(ctx: ProbeContext) -> u32 {
        crate::frame_probes::handle_frame_exit_normal(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn eval_frame_end_rc(ctx: ProbeContext) -> u32 {
        crate::frame_probes::handle_frame_exit_normal(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn eval_frame_end_exc(ctx: ProbeContext) -> u32 {
        crate::frame_probes::handle_frame_exit_exception(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn asyncio_task_init(ctx: ProbeContext) -> u32 {
        crate::task_probes::handle_task_init(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn asyncio_task_step(ctx: ProbeContext) -> u32 {
        crate::task_probes::handle_task_step_entry(&ctx).unwrap_or(());
        0
    }

    #[uretprobe]
    pub fn asyncio_task_step_ret(ctx: RetProbeContext) -> u32 {
        crate::task_probes::handle_task_step_return(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn asyncio_task_eager_start(ctx: ProbeContext) -> u32 {
        crate::task_probes::handle_task_step_entry(&ctx).unwrap_or(());
        0
    }

    #[uretprobe]
    pub fn asyncio_task_eager_start_ret(ctx: RetProbeContext) -> u32 {
        crate::task_probes::handle_task_step_return(&ctx).unwrap_or(());
        0
    }

    #[uprobe]
    pub fn gen_dealloc(ctx: ProbeContext) -> u32 {
        let obj_ptr: u64 = match ctx.arg(0) {
            Some(p) => p,
            None => return 0,
        };
        crate::lifecycle::handle_pyobj_dealloc(obj_ptr);
        0
    }

    #[lsm(hook = "file_open")]
    pub fn ag_file_open(ctx: LsmContext) -> i32 {
        crate::lsm_hooks::handle_file_open(&ctx)
    }

    #[lsm(hook = "bprm_check_security")]
    pub fn ag_bprm_check(ctx: LsmContext) -> i32 {
        crate::lsm_hooks::handle_bprm_check(&ctx)
    }

    #[lsm(hook = "socket_connect")]
    pub fn ag_socket_connect(ctx: LsmContext) -> i32 {
        crate::lsm_hooks::handle_socket_connect(&ctx)
    }

    #[fentry(function = "security_file_open")]
    pub fn ag_fentry_file_open(ctx: FEntryContext) -> i32 {
        crate::lsm_hooks::handle_fentry_file_open(&ctx);
        0
    }

    #[fentry(function = "security_bprm_check")]
    pub fn ag_fentry_bprm_check(ctx: FEntryContext) -> i32 {
        crate::lsm_hooks::handle_fentry_bprm_check(&ctx);
        0
    }

    #[fentry(function = "security_socket_connect")]
    pub fn ag_fentry_socket_connect(ctx: FEntryContext) -> i32 {
        crate::lsm_hooks::handle_fentry_socket_connect(&ctx);
        0
    }
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
