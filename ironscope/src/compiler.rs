/// Policy compiler: converts YAML config into BPF map entries.
/// Resolves paths to (device, inode) pairs for O(1) kernel lookups.
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{bail, Result};
use log::warn;

use crate::config::*;
use crate::rules;
use ironscope_common::types::*;

/// Compiled policy ready for BPF map insertion.
pub struct CompiledPolicy {
    pub tool_name_to_id: HashMap<String, u32>,
    pub agent_pids: Vec<u32>,
    pub fs_rules: Vec<(ToolPolicyKey, u8)>,
    pub exec_rules: Vec<(ToolExecKey, u8)>,
    pub net_rules: Vec<(ToolNetKey, u8)>,
    pub mode: u8,
    pub unknown_tool_policy: u8,
    pub resolver_error_policy: u8,
    pub child_scope: u8,
    pub default_tool_policy: u8,
}

pub struct PolicyCompiler;

impl PolicyCompiler {
    #[cfg(test)]
    pub fn compile(config: &IronScopeSection) -> Result<CompiledPolicy> {
        Self::compile_with_tool_ids(config, |idx, _name| (idx + 1) as u32)
    }

    pub fn compile_with_hashed_tool_ids(config: &IronScopeSection) -> Result<CompiledPolicy> {
        Self::compile_with_tool_ids(config, |_idx, name| rules::fnv1a_32(name))
    }

    fn compile_with_tool_ids<F>(
        config: &IronScopeSection,
        mut tool_id_for: F,
    ) -> Result<CompiledPolicy>
    where
        F: FnMut(usize, &str) -> u32,
    {
        let mut tool_name_to_id: HashMap<String, u32> = HashMap::new();
        let mut fs_rules = Vec::new();
        let mut exec_rules = Vec::new();
        let mut net_rules = Vec::new();

        for (i, tool) in config.tools.iter().enumerate() {
            let tool_id = tool_id_for(i, &tool.name);
            tool_name_to_id.insert(tool.name.clone(), tool_id);

            if let Some(ref fs) = tool.fs {
                Self::compile_fs_rules(tool_id, fs, &mut fs_rules);
            }
            if let Some(ref exec) = tool.exec {
                Self::compile_exec_rules(tool_id, exec, &mut exec_rules);
            }
            if let Some(ref net) = tool.net {
                Self::compile_net_rules(tool_id, net, &mut net_rules);
            }
        }

        // Auto-whitelist DNS resolver IPs for tools with network policy so hostname
        // resolution needed by the tool is not blocked before the socket decision.
        let tool_ids_with_net: Vec<u32> = net_rules
            .iter()
            .map(|(k, _)| k.tool_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if !tool_ids_with_net.is_empty() {
            let dns_ips = Self::discover_dns_resolver_ips();
            if !dns_ips.is_empty() {
                for &tool_id in &tool_ids_with_net {
                    Self::inject_dns_allows(tool_id, &dns_ips, &mut net_rules);
                }
                log::info!("auto-whitelisted {} DNS resolver IP(s)", dns_ips.len());
            }
        }

        let mode = match config.mode.as_str() {
            "monitor" => MODE_MONITOR,
            "enforce" => MODE_ENFORCE,
            other => bail!("invalid mode '{}': expected 'monitor' or 'enforce'", other),
        };
        let unknown_tool_policy = Self::compile_allow_deny_policy(
            &config.unknown_tool_policy,
            UNKNOWN_TOOL_ALLOW,
            UNKNOWN_TOOL_DENY,
            "unknown_tool_policy",
        )?;
        let resolver_error_policy = Self::compile_allow_deny_policy(
            &config.resolver_error_policy,
            RESOLVER_ERROR_ALLOW,
            RESOLVER_ERROR_DENY,
            "resolver_error_policy",
        )?;
        let default_tool_policy = Self::compile_allow_deny_policy(
            &config.default_tool_policy,
            DEFAULT_TOOL_ALLOW,
            DEFAULT_TOOL_DENY,
            "default_tool_policy",
        )?;
        let child_scope = Self::compile_child_scope(&config.agent_child_scope)?;

        Ok(CompiledPolicy {
            tool_name_to_id,
            agent_pids: config.agents.iter().filter_map(|a| a.pid).collect(),
            fs_rules,
            exec_rules,
            net_rules,
            mode,
            unknown_tool_policy,
            resolver_error_policy,
            child_scope,
            default_tool_policy,
        })
    }

    fn compile_allow_deny_policy(
        value: &str,
        allow_value: u8,
        deny_value: u8,
        field_name: &str,
    ) -> Result<u8> {
        match value {
            "allow" => Ok(allow_value),
            "deny" => Ok(deny_value),
            other => bail!(
                "invalid {} '{}': expected 'allow' or 'deny'",
                field_name,
                other
            ),
        }
    }

    fn compile_child_scope(value: &str) -> Result<u8> {
        match value {
            "protect_only_tool_children" => Ok(CHILD_SCOPE_TOOL_ONLY),
            "protect_all_children" => Ok(CHILD_SCOPE_ALL),
            other => bail!(
                "invalid agent_child_scope '{}': expected 'protect_only_tool_children' or 'protect_all_children'",
                other
            ),
        }
    }

    fn compile_fs_rules(tool_id: u32, policy: &FsPolicy, rules: &mut Vec<(ToolPolicyKey, u8)>) {
        for path_str in &policy.allow {
            let clean = path_str.trim_end_matches("/**").trim_end_matches("/*");
            if let Some((dev, ino)) = resolve_path_inode(clean) {
                rules.push((ToolPolicyKey { tool_id, dev, ino }, PERM_ALLOW));
            }
        }
        for path_str in &policy.deny {
            let clean = path_str.trim_end_matches("/**").trim_end_matches("/*");
            if let Some((dev, ino)) = resolve_path_inode(clean) {
                rules.push((ToolPolicyKey { tool_id, dev, ino }, PERM_DENY));
            }
        }
    }

    fn compile_exec_rules(tool_id: u32, policy: &ExecPolicy, rules: &mut Vec<(ToolExecKey, u8)>) {
        for path_str in &policy.allow {
            if path_str == "*" {
                rules.push((
                    ToolExecKey {
                        tool_id,
                        dev: 0,
                        ino: 0,
                    },
                    PERM_ALLOW,
                ));
            } else if let Some((dev, ino)) = resolve_path_inode(path_str) {
                rules.push((ToolExecKey { tool_id, dev, ino }, PERM_ALLOW));
            }
        }
        for path_str in &policy.deny {
            if path_str == "*" {
                rules.push((
                    ToolExecKey {
                        tool_id,
                        dev: 0,
                        ino: 0,
                    },
                    PERM_DENY,
                ));
            } else if let Some((dev, ino)) = resolve_path_inode(path_str) {
                rules.push((ToolExecKey { tool_id, dev, ino }, PERM_DENY));
            }
        }
    }

    fn compile_net_rules(tool_id: u32, policy: &NetPolicy, rules: &mut Vec<(ToolNetKey, u8)>) {
        for entry in &policy.allow {
            if let Some(key) = parse_net_rule(tool_id, entry) {
                rules.push((key, PERM_ALLOW));
            }
        }
        for entry in &policy.deny {
            if let Some(key) = parse_net_rule(tool_id, entry) {
                rules.push((key, PERM_DENY));
            }
        }
    }

    fn inject_dns_allows(tool_id: u32, dns_ips: &[u32], net_rules: &mut Vec<(ToolNetKey, u8)>) {
        for &ip in dns_ips {
            net_rules.push((
                ToolNetKey {
                    prefixlen: 64,
                    tool_id,
                    addr: ip,
                    port: 0,
                    _pad: 0,
                },
                PERM_ALLOW,
            ));
        }
    }

    fn discover_dns_resolver_ips() -> Vec<u32> {
        let mut ips = Vec::new();

        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("nameserver") {
                    let addr_str = rest.trim();
                    if let Some(ip) = parse_ipv4(addr_str) {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }

        if ips.is_empty() {
            if let Some(ip) = parse_ipv4("127.0.0.53") {
                ips.push(ip);
            }
            if let Some(ip) = parse_ipv4("127.0.0.1") {
                ips.push(ip);
            }
        }

        ips
    }
}

fn userspace_dev_to_kernel_dev(dev: u64) -> u32 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff_u64);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff_u64);
    ((major as u32) << 20) | (minor as u32)
}

fn resolve_path_inode(path_str: &str) -> Option<(u32, u64)> {
    let path = Path::new(path_str);
    match std::fs::metadata(path) {
        Ok(meta) => {
            let dev = userspace_dev_to_kernel_dev(meta.dev());
            let ino = meta.ino();
            Some((dev, ino))
        }
        Err(e) => {
            warn!("cannot resolve path '{}': {}", path_str, e);
            None
        }
    }
}

fn parse_net_rule(tool_id: u32, entry: &str) -> Option<ToolNetKey> {
    if entry.contains('/') {
        let parts: Vec<&str> = entry.split('/').collect();
        if parts.len() == 2 {
            let addr = parse_ipv4(parts[0])?;
            let prefix: u32 = parts[1].parse().ok()?;
            return Some(ToolNetKey {
                prefixlen: 32 + prefix,
                tool_id,
                addr,
                port: 0,
                _pad: 0,
            });
        }
    }

    if entry.contains(':') {
        let parts: Vec<&str> = entry.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port: u16 = parts[0].parse().ok()?;
            let host = parts[1];

            let addr = if let Some(ip) = parse_ipv4(host) {
                ip
            } else {
                let addr_str = format!("{}:{}", host, port);
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(std::net::SocketAddr::V4(v4)) = addrs.next() {
                            u32::from_ne_bytes(v4.ip().octets())
                        } else {
                            return None;
                        }
                    }
                    Err(e) => {
                        warn!("DNS resolution failed for '{}': {}", host, e);
                        return None;
                    }
                }
            };

            return Some(ToolNetKey {
                prefixlen: 96,
                tool_id,
                addr,
                port: port.to_be(),
                _pad: 0,
            });
        }
    }

    let addr_str = format!("{}:443", entry);
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(std::net::SocketAddr::V4(v4)) = addrs.next() {
                let addr = u32::from_ne_bytes(v4.ip().octets());
                Some(ToolNetKey {
                    prefixlen: 64,
                    tool_id,
                    addr,
                    port: 0,
                    _pad: 0,
                })
            } else {
                None
            }
        }
        Err(e) => {
            warn!("DNS resolution failed for '{}': {}", entry, e);
            None
        }
    }
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let addr: std::net::Ipv4Addr = s.parse().ok()?;
    Some(u32::from_ne_bytes(addr.octets()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        let key = parse_net_rule(1, "10.0.0.0/8").unwrap();
        assert_eq!(key.tool_id, 1);
        assert_eq!(key.prefixlen, 40);
    }

    #[test]
    fn test_parse_ipv4() {
        let addr = parse_ipv4("192.168.1.1").unwrap();
        assert_eq!(addr, u32::from_ne_bytes([192, 168, 1, 1]));
    }

    #[test]
    fn test_parse_net_rule_uses_consistent_ipv4_encoding() {
        let bare = parse_net_rule(7, "127.0.0.1").unwrap();
        let cidr = parse_net_rule(7, "127.0.0.1/32").unwrap();
        let port = parse_net_rule(7, "127.0.0.1:443").unwrap();

        assert_eq!(bare.addr, cidr.addr);
        assert_eq!(port.addr, cidr.addr);
    }

    #[test]
    fn test_parse_net_rule_port_rules_match_port_bits() {
        let with_port = parse_net_rule(7, "127.0.0.1:443").unwrap();
        let without_port = parse_net_rule(7, "127.0.0.1").unwrap();

        assert_eq!(u16::from_be(with_port.port), 443);
        assert_eq!(with_port.prefixlen, 96);
        assert_eq!(without_port.prefixlen, 64);
    }

    #[test]
    fn test_wildcard_cidr() {
        let key = parse_net_rule(0, "0.0.0.0/0").unwrap();
        assert_eq!(key.prefixlen, 32);
        assert_eq!(key.addr, 0);
    }

    #[test]
    fn test_userspace_dev_to_kernel_dev() {
        assert_eq!(userspace_dev_to_kernel_dev(0xFD01), 265289729);
        assert_eq!(userspace_dev_to_kernel_dev(0x0800), 8388608);
        assert_eq!(userspace_dev_to_kernel_dev(5), 5);
    }

    #[test]
    fn test_resolve_existing_path() {
        let result = resolve_path_inode("/tmp");
        assert!(result.is_some());
        let (dev, ino) = result.unwrap();
        assert!(dev > 0 || ino > 0);
    }

    #[test]
    fn test_resolve_nonexistent_path() {
        let result = resolve_path_inode("/nonexistent/path/xyz");
        assert!(result.is_none());
    }

    #[test]
    fn test_discover_dns_resolver_ips() {
        let ips = PolicyCompiler::discover_dns_resolver_ips();
        assert!(
            !ips.is_empty(),
            "should discover at least one DNS resolver IP"
        );
        let mut seen = std::collections::HashSet::new();
        for ip in &ips {
            assert!(seen.insert(ip), "duplicate DNS resolver IP");
        }
    }

    #[test]
    fn test_inject_dns_allows() {
        let dns_ips = vec![
            parse_ipv4("127.0.0.53").unwrap(),
            parse_ipv4("127.0.0.1").unwrap(),
        ];
        let mut net_rules: Vec<(ToolNetKey, u8)> = vec![];

        net_rules.push((
            ToolNetKey {
                prefixlen: 32,
                tool_id: 1,
                addr: 0,
                port: 0,
                _pad: 0,
            },
            PERM_DENY,
        ));

        PolicyCompiler::inject_dns_allows(1, &dns_ips, &mut net_rules);

        assert_eq!(net_rules.len(), 3);

        let allows: Vec<_> = net_rules
            .iter()
            .filter(|(_, perm)| *perm == PERM_ALLOW)
            .collect();
        assert_eq!(allows.len(), 2);
        for (key, _) in &allows {
            assert_eq!(key.prefixlen, 64);
            assert_eq!(key.tool_id, 1);
        }
    }

    #[test]
    fn test_compile_with_net_deny_includes_dns() {
        let yaml = r#"
ironscope:
  agents:
    - pid: 12345
  tools:
    - name: bash
      net:
        deny:
          - "0.0.0.0/0"
  mode: enforce
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = PolicyCompiler::compile(&config.ironscope).unwrap();

        let deny_count = compiled
            .net_rules
            .iter()
            .filter(|(_, p)| *p == PERM_DENY)
            .count();
        assert!(deny_count >= 1);

        let dns_ips = PolicyCompiler::discover_dns_resolver_ips();
        for dns_ip in &dns_ips {
            let found = compiled.net_rules.iter().any(|(key, perm)| {
                key.tool_id == 1
                    && key.addr == *dns_ip
                    && key.prefixlen == 64
                    && *perm == PERM_ALLOW
            });
            assert!(found, "DNS resolver IP should be whitelisted in net rules");
        }
    }

    #[test]
    fn test_compile_v0_1_runtime_policy_defaults() {
        let yaml = r#"
ironscope: {}
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = PolicyCompiler::compile(&config.ironscope).unwrap();

        assert_eq!(compiled.unknown_tool_policy, UNKNOWN_TOOL_ALLOW);
        assert_eq!(compiled.resolver_error_policy, RESOLVER_ERROR_DENY);
        assert_eq!(compiled.child_scope, CHILD_SCOPE_TOOL_ONLY);
        assert_eq!(compiled.default_tool_policy, DEFAULT_TOOL_ALLOW);
    }

    #[test]
    fn test_compile_v0_1_runtime_policy_overrides() {
        let yaml = r#"
ironscope:
  unknown_tool_policy: deny
  resolver_error_policy: allow
  agent_child_scope: protect_all_children
  default_tool_policy: deny
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = PolicyCompiler::compile(&config.ironscope).unwrap();

        assert_eq!(compiled.unknown_tool_policy, UNKNOWN_TOOL_DENY);
        assert_eq!(compiled.resolver_error_policy, RESOLVER_ERROR_ALLOW);
        assert_eq!(compiled.child_scope, CHILD_SCOPE_ALL);
        assert_eq!(compiled.default_tool_policy, DEFAULT_TOOL_DENY);
    }

    #[test]
    fn test_compile_rejects_invalid_v0_1_runtime_policy() {
        let yaml = r#"
ironscope:
  default_tool_policy: maybe
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let err = match PolicyCompiler::compile(&config.ironscope) {
            Ok(_) => panic!("invalid default_tool_policy should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("default_tool_policy"));
    }

    #[test]
    fn test_compile_basic_config() {
        let yaml = r#"
ironscope:
  agents:
    - pid: 12345
  tools:
    - name: bash
      fs:
        allow:
          - /tmp
      exec:
        deny:
          - "*"
  mode: enforce
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = PolicyCompiler::compile(&config.ironscope).unwrap();

        assert_eq!(compiled.tool_name_to_id["bash"], 1);
        assert_eq!(compiled.mode, MODE_ENFORCE);
        assert!(!compiled.fs_rules.is_empty());
        assert!(!compiled.exec_rules.is_empty());
    }
}
