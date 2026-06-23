use super::resolver::CpythonResolver;
use anyhow::{anyhow, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLangChainTool {
    pub name: String,
    pub tool_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LangChainCodeKind {
    ToolBoundary,
    Other,
}

pub struct LangChainResolver<'a, R: CpythonResolver> {
    cpython: &'a R,
}

impl<'a, R: CpythonResolver> LangChainResolver<'a, R> {
    pub fn new(cpython: &'a R) -> Self {
        Self { cpython }
    }

    pub fn classify_code(&self, code: u64) -> Result<LangChainCodeKind> {
        let qualname = self.cpython.read_code_qualname(code)?;
        if !matches!(
            qualname.as_str(),
            "BaseTool.run" | "BaseTool.arun" | "BaseTool.invoke" | "BaseTool.ainvoke"
        ) {
            return Ok(LangChainCodeKind::Other);
        }

        let filename = self.cpython.read_code_filename(code)?;
        if filename.ends_with("langchain_core/tools/base.py") {
            Ok(LangChainCodeKind::ToolBoundary)
        } else {
            Ok(LangChainCodeKind::Other)
        }
    }

    pub fn resolve_tool(&self, tool_obj: u64) -> Result<ResolvedLangChainTool> {
        let name_ptr = self
            .cpython
            .read_attr(tool_obj, "name")?
            .ok_or_else(|| anyhow!("LangChain tool has no resolvable name attribute"))?;
        let name = self.cpython.read_unicode(name_ptr)?;
        if name.is_empty() {
            return Err(anyhow!("LangChain tool name is empty"));
        }
        let tool_id = crate::rules::fnv1a_32(&name);
        Ok(ResolvedLangChainTool { name, tool_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::python_runtime::cpython::LiveCpythonResolver;
    use anyhow::{bail, Context, Result};
    use serde::Deserialize;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    #[derive(Debug, Deserialize)]
    struct FixtureTool {
        label: String,
        name: String,
        ptr: u64,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureAddrs {
        pid: u32,
        base_invoke_code: u64,
        non_boundary_code: u64,
        tools: Vec<FixtureTool>,
    }

    struct LangChainFixture {
        child: Child,
        addrs: FixtureAddrs,
    }

    impl Drop for LangChainFixture {
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

    fn spawn_fixture() -> Result<LangChainFixture> {
        let script = r#"
import json, os, time
from langchain_core.tools import BaseTool, StructuredTool, tool

@tool
def decorated_lookup(query: str) -> str:
    """Decorated lookup."""
    return query

def structured_lookup(query: str) -> str:
    """Structured lookup."""
    return query
structured = StructuredTool.from_function(structured_lookup, name='structured_lookup')

class SubclassLookupTool(BaseTool):
    name: str = 'subclass_lookup'
    description: str = 'Subclass lookup.'
    def _run(self, query: str) -> str:
        return query
subclass = SubclassLookupTool()

def non_boundary_function():
    return None

tools = [
    {'label': 'decorated', 'name': decorated_lookup.name, 'ptr': id(decorated_lookup)},
    {'label': 'structured', 'name': structured.name, 'ptr': id(structured)},
    {'label': 'subclass', 'name': subclass.name, 'ptr': id(subclass)},
]
print(json.dumps({
    'pid': os.getpid(),
    'base_invoke_code': id(BaseTool.invoke.__code__),
    'non_boundary_code': id(non_boundary_function.__code__),
    'tools': tools,
}), flush=True)
time.sleep(30)
"#;
        let mut child = Command::new(python_bin())
            .arg("-c")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn LangChain resolver fixture")?;
        let stdout = child.stdout.take().context("fixture stdout missing")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("read fixture json line")?;
        let addrs: FixtureAddrs = serde_json::from_str(&line).context("parse fixture json")?;
        Ok(LangChainFixture { child, addrs })
    }

    #[test]
    fn resolves_common_langchain_tool_shapes() -> Result<()> {
        let fixture = spawn_fixture()?;
        let (cpython, detected) = LiveCpythonResolver::detect_for_pid(fixture.addrs.pid)?;
        if detected.version.minor != 12 {
            bail!(
                "test fixture requires the V0.1 CPython 3.12 resolver profile, got {:?}",
                detected.version
            );
        }
        let resolver = LangChainResolver::new(&cpython);

        assert_eq!(
            resolver.classify_code(fixture.addrs.base_invoke_code)?,
            LangChainCodeKind::ToolBoundary
        );
        assert_eq!(
            resolver.classify_code(fixture.addrs.non_boundary_code)?,
            LangChainCodeKind::Other
        );

        for tool in &fixture.addrs.tools {
            let resolved = resolver
                .resolve_tool(tool.ptr)
                .with_context(|| format!("resolve {} fixture", tool.label))?;
            assert_eq!(resolved.name, tool.name);
            assert_eq!(resolved.tool_id, crate::rules::fnv1a_32(&tool.name));
        }
        Ok(())
    }
}
