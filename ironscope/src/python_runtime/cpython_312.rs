use super::cpython::{CpythonOffsets, CpythonProfile, PythonVersion};

pub fn profile(version: PythonVersion) -> CpythonProfile {
    CpythonProfile {
        version,
        pointer_width: 8,
        debug_build: false,
        offsets: CpythonOffsets {
            ob_type: 8,
            unicode_length: 16,
            unicode_state: 32,
            unicode_compact_ascii_data: 40,
            unicode_compact_non_ascii_data: 72,
            type_tp_name: 24,
            type_tp_basicsize: 32,
            type_tp_itemsize: 40,
            type_tp_dictoffset: 288,
            managed_dict_ptr_from_object: -24,
            dict_ma_used: 16,
            dict_ma_keys: 32,
            dict_ma_values: 40,
            dict_keys_log2_size: 8,
            dict_keys_log2_index_bytes: 9,
            dict_keys_kind: 10,
            dict_keys_nentries: 24,
            dict_keys_indices: 32,
            dict_key_entry_size: 24,
            dict_unicode_entry_size: 16,
            dict_key_entry_key: 8,
            dict_key_entry_value: 16,
            dict_unicode_entry_key: 0,
            dict_unicode_entry_value: 8,
            code_filename: 112,
            code_qualname: 128,
            frame_executable: 16,
            frame_localsplus: 72,
        },
    }
}
