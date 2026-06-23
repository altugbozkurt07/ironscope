use serde::Deserialize;
use std::path::PathBuf;

/// Top-level YAML configuration.
#[derive(Debug, Deserialize)]
pub struct IronScopeYamlConfig {
    pub ironscope: IronScopeSection,
}

#[derive(Debug, Deserialize)]
pub struct IronScopeSection {
    #[serde(default)]
    pub agents: Vec<AgentDef>,
    #[serde(default)]
    pub tools: Vec<ToolDef>,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_unknown_tool_policy")]
    pub unknown_tool_policy: String,
    #[serde(default = "default_resolver_error_policy")]
    pub resolver_error_policy: String,
    #[serde(default = "default_agent_child_scope")]
    pub agent_child_scope: String,
    #[serde(default = "default_tool_policy")]
    pub default_tool_policy: String,
}

fn default_mode() -> String {
    "monitor".to_string()
}

fn default_unknown_tool_policy() -> String {
    "allow".to_string()
}

fn default_resolver_error_policy() -> String {
    "deny".to_string()
}

fn default_agent_child_scope() -> String {
    "protect_only_tool_children".to_string()
}

fn default_tool_policy() -> String {
    "allow".to_string()
}

/// Agent definition for the protected process scope.
#[derive(Debug, Deserialize)]
pub struct AgentDef {
    /// Process id of the agent service to protect.
    #[serde(default)]
    pub pid: Option<u32>,
}

/// Tool policy definition.
#[derive(Debug, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub fs: Option<FsPolicy>,
    #[serde(default)]
    pub exec: Option<ExecPolicy>,
    #[serde(default)]
    pub net: Option<NetPolicy>,
}

#[derive(Debug, Deserialize)]
pub struct FsPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExecPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct NetPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl IronScopeYamlConfig {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Create a default zero-config configuration.
    #[cfg(test)]
    pub fn default_config() -> Self {
        Self {
            ironscope: IronScopeSection {
                agents: Vec::new(),
                tools: Vec::new(),
                mode: default_mode(),
                unknown_tool_policy: default_unknown_tool_policy(),
                resolver_error_policy: default_resolver_error_policy(),
                agent_child_scope: default_agent_child_scope(),
                default_tool_policy: default_tool_policy(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
ironscope:
  agents:
    - pid: 1234
  tools:
    - name: get_weather
      fs:
        allow:
          - /tmp
  mode: monitor
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ironscope.agents.len(), 1);
        assert_eq!(config.ironscope.tools.len(), 1);
        assert_eq!(config.ironscope.mode, "monitor");
        assert_eq!(config.ironscope.unknown_tool_policy, "allow");
        assert_eq!(config.ironscope.resolver_error_policy, "deny");
        assert_eq!(
            config.ironscope.agent_child_scope,
            "protect_only_tool_children"
        );
        assert_eq!(config.ironscope.default_tool_policy, "allow");
    }

    #[test]
    fn test_parse_zero_config() {
        let yaml = r#"
ironscope: {}
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.ironscope.agents.is_empty());
        assert!(config.ironscope.tools.is_empty());
        assert_eq!(config.ironscope.mode, "monitor");
        assert_eq!(config.ironscope.unknown_tool_policy, "allow");
        assert_eq!(config.ironscope.resolver_error_policy, "deny");
        assert_eq!(
            config.ironscope.agent_child_scope,
            "protect_only_tool_children"
        );
        assert_eq!(config.ironscope.default_tool_policy, "allow");
    }

    #[test]
    fn test_parse_v0_1_runtime_policy_fields() {
        let yaml = r#"
ironscope:
  unknown_tool_policy: deny
  resolver_error_policy: allow
  agent_child_scope: protect_all_children
  default_tool_policy: deny
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ironscope.unknown_tool_policy, "deny");
        assert_eq!(config.ironscope.resolver_error_policy, "allow");
        assert_eq!(config.ironscope.agent_child_scope, "protect_all_children");
        assert_eq!(config.ironscope.default_tool_policy, "deny");
    }

    #[test]
    fn test_default_config() {
        let config = IronScopeYamlConfig::default_config();
        assert!(config.ironscope.agents.is_empty());
        assert_eq!(config.ironscope.mode, "monitor");
        assert_eq!(config.ironscope.unknown_tool_policy, "allow");
        assert_eq!(config.ironscope.resolver_error_policy, "deny");
        assert_eq!(
            config.ironscope.agent_child_scope,
            "protect_only_tool_children"
        );
        assert_eq!(config.ironscope.default_tool_policy, "allow");
    }

    #[test]
    fn test_parse_pid_match() {
        let yaml = r#"
ironscope:
  agents:
    - pid: 1234
  tools: []
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ironscope.agents[0].pid, Some(1234));
    }

    #[test]
    fn test_parse_full_policy() {
        let yaml = r#"
ironscope:
  agents:
    - pid: 1234
  tools:
    - name: bash
      fs:
        allow:
          - /tmp
          - /home/user/workspace
        deny:
          - /etc/shadow
          - /etc/passwd
      exec:
        allow:
          - /usr/bin/grep
          - /usr/bin/find
        deny:
          - /usr/bin/rm
      net:
        allow:
          - 0.0.0.0/0
  mode: enforce
"#;
        let config: IronScopeYamlConfig = serde_yaml::from_str(yaml).unwrap();
        let tools = &config.ironscope.tools;
        assert_eq!(tools[0].name, "bash");
        assert!(tools[0].fs.is_some());
        assert!(tools[0].exec.is_some());
        assert!(tools[0].net.is_some());
        assert_eq!(config.ironscope.mode, "enforce");
    }
}
