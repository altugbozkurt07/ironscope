use anyhow::Result;

pub trait CpythonResolver {
    fn read_type_ptr(&self, obj: u64) -> Result<u64>;
    fn read_type_name(&self, obj: u64) -> Result<String>;
    fn read_unicode(&self, obj: u64) -> Result<String>;
    fn read_dict_item(&self, dict: u64, key: &str) -> Result<Option<u64>>;
    fn read_attr(&self, obj: u64, key: &str) -> Result<Option<u64>>;
    fn read_code_filename(&self, code: u64) -> Result<String>;
    fn read_code_qualname(&self, code: u64) -> Result<String>;
}
