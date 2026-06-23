use anyhow::{Context, Result};
use ironscope_common::types::RootRule;
use std::path::Path;

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const MAX_HASH_BYTES: usize = 64;

pub fn fnv1a_64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let len = bytes.len().min(MAX_HASH_BYTES);
    let mut hash = FNV_OFFSET;
    for i in 0..len {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[derive(serde::Deserialize)]
struct RulesFile {
    rules: Vec<RuleEntry>,
}

#[derive(serde::Deserialize)]
struct RuleEntry {
    qualname: String,
    kind: u8,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    extractor_kind: u32,
    #[serde(default)]
    slot: u32,
}

pub fn load_rules(path: &Path) -> Result<Vec<RootRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read rules file: {}", path.display()))?;
    let file: RulesFile = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse rules file: {}", path.display()))?;

    let mut rules = Vec::new();
    for entry in &file.rules {
        let qualname_hash = fnv1a_64(&entry.qualname);
        let filename_hash = entry.filename.as_deref().map(fnv1a_64).unwrap_or(0);
        rules.push(RootRule {
            kind: entry.kind,
            _rule_pad: [0; 3],
            slot_index: entry.slot,
            extractor_kind: entry.extractor_kind,
            _rule_pad2: 0,
            filename_hash,
            qualname_hash,
            firstline: 0,
            _rule_pad3: 0,
        });
    }
    Ok(rules)
}

pub fn fnv1a_32(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut h: u32 = 0x811c9dc5;
    for &b in bytes.iter().take(64) {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    if h == 0 {
        1
    } else {
        h
    }
}
