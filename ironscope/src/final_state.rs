use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Clone)]
pub struct RuntimePyEvent {
    pub kind: u8,
    pub kind_str: String,
    pub ctx_id: u64,
    pub tool_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub ts_ns: u64,
    pub carrier_ptr: u64,
    pub aux: u64,
}

#[derive(Serialize)]
pub struct ToolDispatchInfo {
    pub name: String,
    pub count: u32,
}

#[derive(Serialize, Clone)]
pub struct ResolverProtocolEvent {
    pub kind: u8,
    pub kind_str: String,
    pub code_kind: u8,
    pub ctx_id: u64,
    pub self_ptr: u64,
    pub type_ptr: u64,
    pub frame_ptr: u64,
    pub code_ptr: u64,
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
}

#[derive(Serialize, Clone)]
pub struct GuardAuditEvent {
    pub kind: u8,
    pub kind_str: String,
    pub ctx_id: u64,
    pub tool_id: u32,
    pub tool_name: String,
    pub identity_state: String,
    pub policy_source: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub action: String,
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
}

#[derive(Serialize)]
pub struct BracketCheck {
    pub total_guard_events: u32,
    pub attributed_guard_events: u32,
    pub bracket_violations: u32,
}

#[derive(Serialize)]
pub struct RuntimeFinalState {
    #[serde(rename = "TOOL_CTX")]
    pub tool_ctx_count: u32,
    #[serde(rename = "TASK_CTX")]
    pub task_ctx_count: u32,
    #[serde(rename = "TASK_CTX_STACK")]
    pub task_ctx_stack_count: u32,
    #[serde(rename = "TASK_CTX_DEPTH")]
    pub task_ctx_depth_count: u32,
    #[serde(rename = "PENDING_TOOL_CLOSE")]
    pub pending_tool_close_count: u32,
    #[serde(rename = "PENDING_FRAME_TOOL")]
    pub pending_frame_tool_count: u32,
    #[serde(rename = "FORK_CTX")]
    pub fork_ctx_count: u32,
    #[serde(rename = "WORKITEM_CTX")]
    pub workitem_ctx_count: u32,
    #[serde(rename = "PYTHREAD_OBJ_CTX")]
    pub pythread_obj_ctx_count: u32,
    #[serde(rename = "PYTHREAD_OBJ_THREAD")]
    pub pythread_obj_thread_count: u32,
    #[serde(rename = "FRAME_CTX")]
    pub frame_ctx_count: u32,
    #[serde(rename = "THREAD_ACTIVE_CTX")]
    pub thread_active_ctx_count: u32,
    #[serde(rename = "THREAD_ACTIVE_TASK")]
    pub thread_active_task_count: u32,
    #[serde(rename = "THREAD_CTX_STACK")]
    pub thread_ctx_stack_count: u32,
    #[serde(rename = "THREAD_CTX_DEPTH")]
    pub thread_ctx_depth_count: u32,
    #[serde(rename = "THREADPOOL_WORKER_FRAME")]
    pub threadpool_worker_frame_count: u32,
    #[serde(rename = "THREADPOOL_WORKER_CTX")]
    pub threadpool_worker_ctx_count: u32,
    #[serde(rename = "THREADPOOL_WORKITEM_THREAD")]
    pub threadpool_workitem_thread_count: u32,
    #[serde(rename = "THREAD_CURRENT_FRAME")]
    pub thread_current_frame_count: u32,
    #[serde(rename = "THREAD_TSTATE")]
    pub thread_tstate_count: u32,
    #[serde(rename = "FRAME_ENTRY_STASH")]
    pub frame_entry_stash_count: u32,
    #[serde(rename = "FRAME_STASH_DEPTH")]
    pub frame_stash_depth_count: u32,
    #[serde(rename = "WORKER_RUN_STACK")]
    pub worker_run_stack_count: u32,
    #[serde(rename = "WORKER_RUN_CARRIER")]
    pub worker_run_carrier_count: u32,
    #[serde(rename = "WORKER_RUN_DEPTH")]
    pub worker_run_active_count: u32,
}

#[derive(Serialize)]
pub struct RuntimeAuditReport {
    pub schema_version: &'static str,
    pub runtime: &'static str,
    pub py_events: Vec<RuntimePyEvent>,
    pub resolver_events: Vec<ResolverProtocolEvent>,
    pub guard_events: Vec<GuardAuditEvent>,
    pub balanced: bool,
    pub orphan_frame_ctx: u32,
    pub tool_dispatches: HashMap<String, ToolDispatchInfo>,
    pub audit_unresolved: u32,
    pub audit_unattributed: u32,
    pub task_bind_count: u32,
    pub task_unbind_count: u32,
    pub worker_bind_count: u32,
    pub worker_unbind_count: u32,
    pub stack_overflow_count: u32,
    pub dealloc_cleanup_count: u32,
    pub bracket_check: BracketCheck,
    pub final_state: RuntimeFinalState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_event_schema_includes_identity_and_policy_source() {
        let event = GuardAuditEvent {
            kind: 1,
            kind_str: "FILE_OPEN".to_string(),
            ctx_id: 42,
            tool_id: 7,
            tool_name: "read_file".to_string(),
            identity_state: "known_tool".to_string(),
            policy_source: "tool".to_string(),
            path: "/tmp/file".to_string(),
            addr: None,
            port: None,
            action: "allow".to_string(),
            ts_ns: 123,
            pid: 100,
            tid: 101,
        };

        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["identity_state"], "known_tool");
        assert_eq!(value["policy_source"], "tool");
    }
}
