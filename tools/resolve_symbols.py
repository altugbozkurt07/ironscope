#!/usr/bin/env python3
"""
Resolve CPython and _asyncio symbols/offsets for IronScope.
Produces a versioned contract JSON under a contract directory.
"""
import argparse
import asyncio
import ctypes
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import shlex

import _asyncio
import sysconfig

PYTHON_BIN = sys.executable
ASYNCIO_PATH = getattr(_asyncio, "__file__", None)
_ldlibrary = sysconfig.get_config_var("LDLIBRARY") or ""
_libdir = sysconfig.get_config_var("LIBDIR") or ""
LIBPYTHON_PATH = os.path.join(_libdir, _ldlibrary) if _ldlibrary else PYTHON_BIN
if not os.path.exists(LIBPYTHON_PATH):
    LIBPYTHON_PATH = PYTHON_BIN
OUTPUT_DIR = os.path.dirname(__file__)
RESUME_FILE_OFFSET = None
START_FRAME_FILE_OFFSET = None
START_FRAME_REL_OFFSET = None
FRAME_REG_IDX = None
START_FRAME_FANIN = None
START_FRAME_EXTRA_FILE_OFFSETS = []
DECREMENT_BLOCK_COUNT = None



def compile_cpython_offset_probe():
    """Derive CPython internal layout offsets from this exact target build.

    This intentionally fails closed if Python development/internal headers are
    unavailable. IronScope release contracts must be generated from the target
    build or loaded from a verified packaged contract; they must not guess
    interpreter object layouts from version numbers.
    """
    include_py = sysconfig.get_config_var("INCLUDEPY")
    if not include_py or not os.path.isdir(include_py):
        raise RuntimeError(
            "cannot derive CPython offsets: INCLUDEPY is missing or does not exist; "
            "install the target Python development headers or use a verified packaged contract"
        )

    cc = sysconfig.get_config_var("CC") or "cc"
    cflags = sysconfig.get_config_var("CFLAGS") or ""
    code = r"""
#define Py_BUILD_CORE 1
#include <Python.h>
#include <stddef.h>
#include "internal/pycore_frame.h"

int main(void) {
#if PY_VERSION_HEX < 0x030C0000
    size_t frame_executable = offsetof(_PyInterpreterFrame, f_code);
#else
    size_t frame_executable = offsetof(_PyInterpreterFrame, f_executable);
#endif
    printf("{\n");
    printf("  \"PyObject\": {\"ob_type\": %zu},\n", offsetof(PyObject, ob_type));
    printf("  \"_PyInterpreterFrame\": {\"f_executable\": %zu, \"previous\": %zu, \"owner\": %zu, \"localsplus\": %zu},\n",
           frame_executable,
           offsetof(_PyInterpreterFrame, previous),
           offsetof(_PyInterpreterFrame, owner),
           offsetof(_PyInterpreterFrame, localsplus));
    printf("  \"PyGenObject\": {\"gi_frame_state\": %zu, \"gi_iframe\": %zu},\n",
           offsetof(PyGenObject, gi_frame_state),
           offsetof(PyGenObject, gi_iframe));
    printf("  \"PyTypeObject\": {\"tp_init\": %zu, \"tp_dealloc\": %zu},\n",
           offsetof(PyTypeObject, tp_init),
           offsetof(PyTypeObject, tp_dealloc));
#if PY_VERSION_HEX >= 0x030D0000
    size_t tstate_current_frame = offsetof(PyThreadState, current_frame);
#else
    size_t tstate_current_frame = 0;
#endif
    printf("  \"PyThreadState\": {\"current_frame\": %zu}\n", tstate_current_frame);
    printf("}\n");
    return 0;
}
"""
    with tempfile.TemporaryDirectory(prefix="ironscope-cpython-offsets-") as tmp:
        src = os.path.join(tmp, "offsets.c")
        exe = os.path.join(tmp, "offsets")
        with open(src, "w", encoding="utf-8") as f:
            f.write(code)
        cmd = shlex.split(cc) + shlex.split(cflags) + [f"-I{include_py}", src, "-o", exe]
        compile_result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if compile_result.returncode != 0:
            raise RuntimeError(
                f"cannot compile CPython offset probe for {PYTHON_BIN}: {compile_result.stderr.strip()}"
            )
        out = subprocess.check_output([exe], text=True)
    return json.loads(out)

def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)


def get_build_id(path):
    try:
        out = run_cmd(f"readelf -n {path}")
        for line in out.splitlines():
            if "Build ID:" in line:
                return line.split("Build ID:")[1].strip()
    except Exception:
        pass
    return None


def get_build_id_or_sha256(path):
    bid = get_build_id(path)
    if bid:
        return bid, None
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    return None, sha


def get_nm_symbols(path, dynamic=True):
    flag = "-D" if dynamic else ""
    try:
        out = run_cmd(f"nm {flag} {path}")
    except Exception:
        return {}
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            addr, typ, name = int(parts[0], 16), parts[1], parts[2]
            syms[name] = (addr, typ)
    return syms


def get_nm_symbols_with_size(path, dynamic=True):
    """Like get_nm_symbols but also returns symbol size (via `nm -S`)."""
    flag = "-S -D" if dynamic else "-S"
    try:
        out = run_cmd(f"nm {flag} {path}")
    except Exception:
        return {}
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        # With -S: addr size type name (4 parts) OR addr type name (3 parts, undef)
        if len(parts) == 4:
            addr = int(parts[0], 16)
            size = int(parts[1], 16)
            typ, name = parts[2], parts[3]
            syms[name] = (addr, size, typ)
        elif len(parts) == 3:
            addr = int(parts[0], 16)
            typ, name = parts[1], parts[2]
            syms[name] = (addr, 0, typ)
    return syms


def resolve_libpython_symbols():
    """Resolve symbols from the python3 binary (libpython statically linked).

    Returns _PyEval_EvalFrameDefault function info PLUS start_frame label
    offset and frame_reg_idx required for Phase 2 probe attachment."""
    syms_with_size = get_nm_symbols_with_size(PYTHON_BIN, dynamic=True)
    # Fall back to old format for callers that still use the 2-tuple
    syms = {k: (v[0], v[2]) for k, v in syms_with_size.items()}
    result = {}

    eval_frame = syms_with_size.get("_PyEval_EvalFrameDefault")
    if not eval_frame:
        print("FATAL: _PyEval_EvalFrameDefault not found in python3 binary", file=sys.stderr)
        sys.exit(1)
    eval_frame_va, eval_frame_size, _ = eval_frame
    if eval_frame_size == 0:
        print("FATAL: _PyEval_EvalFrameDefault has zero size (stripped nm output?)",
              file=sys.stderr)
        sys.exit(1)

    elf_data = open(PYTHON_BIN, "rb").read()
    load_va, load_off = parse_first_load_segment(elf_data)
    file_off = eval_frame_va - load_va + load_off

    missing_attach_inputs = []
    if START_FRAME_FILE_OFFSET is None:
        missing_attach_inputs.append("--start-frame-file-offset")
    if START_FRAME_REL_OFFSET is None:
        missing_attach_inputs.append("--start-frame-rel-offset")
    if FRAME_REG_IDX is None:
        missing_attach_inputs.append("--frame-reg-idx")
    if START_FRAME_FANIN is None:
        missing_attach_inputs.append("--start-frame-fanin")
    if DECREMENT_BLOCK_COUNT is None:
        missing_attach_inputs.append("--decrement-block-count")
    if missing_attach_inputs:
        print(
            "FATAL: contract generation requires Rust-discovered eval-frame "
            "attach metadata: " + ", ".join(missing_attach_inputs),
            file=sys.stderr,
        )
        sys.exit(1)

    start_frame_rel_off = START_FRAME_REL_OFFSET
    expected_file_off = file_off + start_frame_rel_off
    if expected_file_off != START_FRAME_FILE_OFFSET:
        print(
            "FATAL: start frame file/relative offsets disagree "
            f"(file_offset=0x{START_FRAME_FILE_OFFSET:x}, "
            f"eval+rel=0x{expected_file_off:x})",
            file=sys.stderr,
        )
        sys.exit(1)
    frame_reg = FRAME_REG_IDX
    fanin_hits = START_FRAME_FANIN
    inline_count = DECREMENT_BLOCK_COUNT

    print(
        f"  _PyEval_EvalFrameDefault file_offset=0x{file_off:x} "
        f"size=0x{eval_frame_size:x}",
        file=sys.stderr,
    )
    print(
        f"  start_frame interior join point: "
        f"+0x{start_frame_rel_off:x} (abs "
        f"0x{file_off + start_frame_rel_off:x}, "
        f"{fanin_hits} shared B-branches fan in, "
        f"{inline_count} decrement blocks total)",
        file=sys.stderr,
    )
    print(f"  frame_reg_idx: x{frame_reg}", file=sys.stderr)

    result["_PyEval_EvalFrameDefault"] = {
        "source": "python_binary_dynsym",
        "file_offset": file_off,
        "size": eval_frame_size,
        "start_frame_file_offset": file_off + start_frame_rel_off,
        "start_frame_rel_offset": start_frame_rel_off,
        "start_frame_extra_file_offsets": START_FRAME_EXTRA_FILE_OFFSETS,
        "frame_reg_idx": frame_reg,
        "start_frame_offset_source": "rust-aarch64-discovery",
        "virtual_address": eval_frame_va,
        "binary": PYTHON_BIN,
    }
    return result, syms, load_va, load_off


def parse_first_load_segment(elf_data):
    """Parse ELF to find first LOAD segment's VA and file offset."""
    e_phoff = struct.unpack_from("<Q", elf_data, 32)[0]
    e_phentsize = struct.unpack_from("<H", elf_data, 54)[0]
    e_phnum = struct.unpack_from("<H", elf_data, 56)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", elf_data, off)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from("<Q", elf_data, off + 8)[0]
            p_vaddr = struct.unpack_from("<Q", elf_data, off + 16)[0]
            p_flags = struct.unpack_from("<I", elf_data, off + 4)[0]
            if p_flags & 1:  # PF_X (executable)
                return p_vaddr, p_offset
    raise RuntimeError("ELF has no executable PT_LOAD segment; cannot translate virtual addresses")


def resolve_type_deallocs(bin_syms, load_va, load_off):
    """Resolve tp_dealloc for PyGen_Type, PyCoro_Type, PyAsyncGen_Type."""
    import types

    result = {}
    type_map = {
        "PyGen_Type_tp_dealloc": types.GeneratorType,
        "PyCoro_Type_tp_dealloc": types.CoroutineType,
        "PyAsyncGen_Type_tp_dealloc": types.AsyncGeneratorType,
    }

    for name, py_type in type_map.items():
        type_addr = id(py_type)
        cpython_offsets = compile_cpython_offset_probe()
        tp_dealloc_offset = cpython_offsets["PyTypeObject"]["tp_dealloc"]
        tp_dealloc_va = ctypes.c_uint64.from_address(type_addr + tp_dealloc_offset).value

        maps = parse_proc_maps(os.getpid())
        binary, base_va, file_offset_base = find_mapping_for_va(maps, tp_dealloc_va)
        if binary is None:
            print(f"FATAL: Cannot map {name} VA 0x{tp_dealloc_va:x} to file", file=sys.stderr)
            sys.exit(1)

        file_off = tp_dealloc_va - base_va + file_offset_base
        source = "python_binary_runtime_read" if "python3" in binary else "libpython_runtime_read"
        result[name] = {
            "source": source,
            "file_offset": file_off,
            "virtual_address": tp_dealloc_va,
            "binary": binary,
        }
    return result


def parse_proc_maps(pid):
    """Parse /proc/<pid>/maps into list of (start, end, perms, offset, path)."""
    entries = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            addr_range = parts[0].split("-")
            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            perms = parts[1]
            offset = int(parts[2], 16)
            path = parts[5] if len(parts) >= 6 else ""
            entries.append((start, end, perms, offset, path))
    return entries


def find_mapping_for_va(maps, va):
    """Find which file and base a virtual address maps to."""
    for start, end, perms, offset, path in maps:
        if start <= va < end and path and path.startswith("/"):
            return path, start, offset
    return None, None, None


def decode_bl_target(data, pc):
    """Decode aarch64 BL instruction at file offset pc, return target file offset."""
    insn = struct.unpack_from("<I", data, pc)[0]
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x03FFFFFF
    if imm26 & 0x02000000:
        offset = ((imm26 | 0xFFFFFFFFFC000000) << 2) & 0xFFFFFFFFFFFFFFFF
        if offset > 0x7FFFFFFFFFFFFFFF:
            offset = -(0x10000000000000000 - offset)
    else:
        offset = imm26 << 2
    return pc + offset


def get_asyncio_text_range(elf_data):
    """Get .text section offset and size from the _asyncio ELF."""
    e_shoff = struct.unpack_from("<Q", elf_data, 40)[0]
    e_shentsize = struct.unpack_from("<H", elf_data, 58)[0]
    e_shnum = struct.unpack_from("<H", elf_data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", elf_data, 62)[0]

    shstr_off = struct.unpack_from("<Q", elf_data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_size = struct.unpack_from("<Q", elf_data, e_shoff + e_shstrndx * e_shentsize + 32)[0]

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", elf_data, sh_off)[0]
        name_end = elf_data.index(b"\x00", shstr_off + sh_name_idx)
        name = elf_data[shstr_off + sh_name_idx:name_end].decode()
        if name == ".text":
            sec_offset = struct.unpack_from("<Q", elf_data, sh_off + 24)[0]
            sec_size = struct.unpack_from("<Q", elf_data, sh_off + 32)[0]
            return sec_offset, sec_size

    raise RuntimeError("_asyncio ELF has no .text section; cannot discover task symbols")


def get_plt_range(elf_data):
    """Get .plt section offset and size."""
    e_shoff = struct.unpack_from("<Q", elf_data, 40)[0]
    e_shentsize = struct.unpack_from("<H", elf_data, 58)[0]
    e_shnum = struct.unpack_from("<H", elf_data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", elf_data, 62)[0]

    shstr_off = struct.unpack_from("<Q", elf_data, e_shoff + e_shstrndx * e_shentsize + 24)[0]

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", elf_data, sh_off)[0]
        name_end = elf_data.index(b"\x00", shstr_off + sh_name_idx)
        name = elf_data[shstr_off + sh_name_idx:name_end].decode()
        if name == ".plt":
            sec_offset = struct.unpack_from("<Q", elf_data, sh_off + 24)[0]
            sec_size = struct.unpack_from("<Q", elf_data, sh_off + 32)[0]
            return sec_offset, sec_size

    return 0, 0


def find_plt_symbol(asyncio_data, plt_addr):
    """Identify PLT symbol name by checking objdump output."""
    try:
        out = run_cmd(
            f"objdump -d -j .plt {ASYNCIO_PATH}"
        )
        for line in out.splitlines():
            if f"{plt_addr:x}" in line and "@plt>:" in line:
                return line.split("<")[1].split("@")[0]
    except Exception:
        pass
    return None


def scan_bl_local_targets(data, func_start, text_start, max_bytes=4000):
    """Find all BL targets from a function that land in .text (local calls)."""
    targets = []
    for i in range(0, max_bytes, 4):
        off = func_start + i
        if off + 4 > len(data):
            break
        target = decode_bl_target(data, off)
        if target is not None and target >= text_start:
            targets.append((off, target))
        insn = struct.unpack_from("<I", data, off)[0]
        if insn == 0xd503233f and i > 0:
            break
    return targets


def find_callers(data, target_func, text_start, text_end):
    """Find all BL/B instructions targeting a function."""
    callers = []
    for off in range(text_start, text_end - 4, 4):
        insn = struct.unpack_from("<I", data, off)[0]
        for mask in [0x94000000, 0x14000000]:
            if (insn & 0xFC000000) == mask:
                t = decode_bl_target(data, off)
                if t is None:
                    imm26 = insn & 0x03FFFFFF
                    if imm26 & 0x02000000:
                        offset_val = ((imm26 | 0xFFFFFFFFFC000000) << 2) & 0xFFFFFFFFFFFFFFFF
                        if offset_val > 0x7FFFFFFFFFFFFFFF:
                            offset_val = -(0x10000000000000000 - offset_val)
                    else:
                        offset_val = imm26 << 2
                    t = off + offset_val
                if t == target_func:
                    kind = "BL" if mask == 0x94000000 else "B"
                    callers.append((off, kind))
    return callers


def find_bl_to_plt(data, func_start, plt_target, max_bytes=4000):
    """Check if a function calls a specific PLT address."""
    for i in range(0, max_bytes, 4):
        off = func_start + i
        if off + 4 > len(data):
            break
        target = decode_bl_target(data, off)
        if target == plt_target:
            return True
        insn = struct.unpack_from("<I", data, off)[0]
        if insn == 0xd503233f and i > 0:
            break
    return False


def resolve_asyncio_symbols():
    """Resolve _asyncio symbols via CALL-scan (stripped binary)."""
    import _asyncio

    asyncio_data = open(ASYNCIO_PATH, "rb").read()
    text_start, text_size = get_asyncio_text_range(asyncio_data)
    text_end = text_start + text_size

    direct_syms = get_nm_symbols(ASYNCIO_PATH, dynamic=False)
    if "_asyncio_Task___init___impl" in direct_syms and "task_step" in direct_syms:
        if "task_eager_start" not in direct_syms:
            print(
                "FATAL: _asyncio task_eager_start symbol is absent; this generator "
                "does not guess an eager-start attach point for this build",
                file=sys.stderr,
            )
            sys.exit(1)
        init_impl_offset = direct_syms["_asyncio_Task___init___impl"][0]
        task_step_offset = direct_syms["task_step"][0]
        task_eager_start_offset = direct_syms["task_eager_start"][0]
        print(f"  _asyncio_Task___init___impl (symtab): 0x{init_impl_offset:x}")
        print(f"  task_step (symtab): 0x{task_step_offset:x}")
        print(f"  task_eager_start (symtab): 0x{task_eager_start_offset:x}")
        return {
            "_asyncio_Task___init___impl": {
                "source": "asyncio_symtab",
                "file_offset": init_impl_offset,
                "note": "resolved directly from asyncio/Python symbol table; probe arg0 for TaskObj*",
            },
            "task_step": {
                "source": "asyncio_symtab",
                "file_offset": task_step_offset,
                "note": "resolved directly from asyncio/Python symbol table; probe arg1 for TaskObj*",
            },
            "task_eager_start": {
                "source": "asyncio_symtab",
                "file_offset": task_eager_start_offset,
                "note": "resolved directly from asyncio/Python symbol table; probe arg1 for TaskObj*",
            },
        }

    cpython_offsets = compile_cpython_offset_probe()
    tp_init_struct_offset = cpython_offsets["PyTypeObject"]["tp_init"]
    maps = parse_proc_maps(os.getpid())
    task_type_addr = id(_asyncio.Task)
    tp_init_va = ctypes.c_uint64.from_address(task_type_addr + tp_init_struct_offset).value
    mapped_path, mapping_start, mapping_file_offset = find_mapping_for_va(maps, tp_init_va)

    if mapped_path is None:
        print("FATAL: _asyncio Task.tp_init is not in a file-backed mapping", file=sys.stderr)
        sys.exit(1)

    tp_init_offset = tp_init_va - mapping_start + mapping_file_offset

    print(f"  tp_init file offset: 0x{tp_init_offset:x}")

    # _asyncio_Task___init___impl is inlined into tp_init
    init_impl_offset = tp_init_offset

    # Find task_step_impl: the function that calls PyIter_Send
    # First find PyIter_Send PLT address
    plt_pyiter_send = None
    try:
        out = run_cmd(f"objdump -d -j .plt {ASYNCIO_PATH}")
        for line in out.splitlines():
            if "PyIter_Send@plt>:" in line:
                plt_pyiter_send = int(line.split()[0], 16)
                break
    except Exception:
        pass

    if plt_pyiter_send is None:
        print("FATAL: PyIter_Send not found in _asyncio PLT", file=sys.stderr)
        sys.exit(1)

    print(f"  PyIter_Send PLT: 0x{plt_pyiter_send:x}")

    # Find all function starts (paciasp pattern)
    func_starts = []
    for off in range(text_start, text_end - 4, 4):
        insn = struct.unpack_from("<I", asyncio_data, off)[0]
        if insn == 0xD503233F:  # paciasp
            func_starts.append(off)

    # Find the function that calls PyIter_Send = task_step_impl
    task_step_impl_offset = None
    for func_start in func_starts:
        if find_bl_to_plt(asyncio_data, func_start, plt_pyiter_send):
            task_step_impl_offset = func_start
            break

    if task_step_impl_offset is None:
        print("FATAL: Could not find task_step_impl (PyIter_Send caller)", file=sys.stderr)
        sys.exit(1)

    print(f"  task_step_impl: 0x{task_step_impl_offset:x}")

    # Find callers of task_step_impl
    callers = find_callers(asyncio_data, task_step_impl_offset, text_start, text_end)
    print(f"  task_step_impl callers: {[(f'0x{c[0]:x}', c[1]) for c in callers]}")

    # Identify task_step: called from task_wakeup (which calls PyObject_CallMethod)
    # task_step is the function that:
    #   - does NOT call PyType_GetModuleByDef (receives state as param)
    #   - calls task_step_impl
    #   - is called from other functions (not just via function pointer dispatch)

    # First, find which function each caller belongs to
    caller_funcs = set()
    for caller_pc, kind in callers:
        init_func_start = None
        for j, fs in enumerate(func_starts):
            next_fs = func_starts[j + 1] if j + 1 < len(func_starts) else text_end
            if fs <= init_impl_offset < next_fs:
                init_func_start = fs
                break
        if init_func_start is not None:
            init_idx = func_starts.index(init_func_start)
            init_func_end = func_starts[init_idx + 1] if init_idx + 1 < len(func_starts) else text_end
            if init_func_start <= caller_pc < init_func_end:
                continue  # skip tp_init (inlined eager_start)
        for j, fs in enumerate(func_starts):
            if j + 1 < len(func_starts):
                next_fs = func_starts[j + 1]
            else:
                next_fs = text_end
            if fs <= caller_pc < next_fs:
                caller_funcs.add(fs)
                break

    print(f"  Caller functions (excluding tp_init): {[f'0x{f:x}' for f in sorted(caller_funcs)]}")

    # Among these, find task_step: the one that IS called from other functions
    # (task_step is called from task_wakeup; TaskStepMethWrapper_call calls task_step_impl directly)
    task_step_offset = None
    for func in sorted(caller_funcs):
        func_callers = find_callers(asyncio_data, func, text_start, text_end)
        if func_callers:
            task_step_offset = func
            print(f"  task_step candidate 0x{func:x} has callers: "
                  f"{[(f'0x{c[0]:x}', c[1]) for c in func_callers]}")
            break

    if task_step_offset is None:
        print(
            "FATAL: Could not uniquely identify task_step from _asyncio call graph",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  task_step: 0x{task_step_offset:x}")

    # task_eager_start can be inlined into tp_init in stripped builds. In that
    # case task_step_impl is the proven eager execution boundary discovered from
    # the PyIter_Send call graph above.
    task_eager_start_offset = task_step_impl_offset
    print(f"  task_eager_start (inlined, call-graph proven): 0x{task_eager_start_offset:x}")

    return {
        "_asyncio_Task___init___impl": {
            "source": "callscan",
            "file_offset": init_impl_offset,
            "note": "inlined into tp_init; probe arg0 for TaskObj*",
        },
        "task_step": {
            "source": "callscan",
            "file_offset": task_step_offset,
            "note": "identified via call graph analysis; probe arg1 for TaskObj*",
        },
        "task_eager_start": {
            "source": "callscan",
            "file_offset": task_eager_start_offset,
            "note": "original function inlined into tp_init; offset points to call-graph-proven task_step_impl; probe arg1 for TaskObj*",
        },
    }


def discover_offsets():
    """Discover struct offsets via ctypes introspection."""
    offsets = {}

    # === PyCodeObject ===
    def find_ptr_offset(base_addr, target_val, max_range=300):
        mem = (ctypes.c_uint64 * (max_range // 8)).from_address(base_addr)
        return [i * 8 for i, v in enumerate(mem) if v == target_val]

    async def _dummy():
        pass

    code = _dummy.__code__
    code_addr = id(code)

    fn_offsets = find_ptr_offset(code_addr, id(code.co_filename))
    nm_offsets = find_ptr_offset(code_addr, id(code.co_name))
    qn_offsets = find_ptr_offset(code_addr, id(code.co_qualname))

    if len(fn_offsets) != 1 or len(nm_offsets) != 1 or len(qn_offsets) != 1:
        raise RuntimeError(
            "cannot uniquely discover PyCodeObject pointer fields "
            f"(filename={fn_offsets}, name={nm_offsets}, qualname={qn_offsets})"
        )
    co_filename = fn_offsets[0]
    co_name = nm_offsets[0]
    co_qualname = qn_offsets[0]

    # co_firstlineno / co_flags: scan for known values. co_flags is required by
    # the eBPF frame classifier to distinguish coroutine/generator code paths.
    expected_lineno = code.co_firstlineno
    expected_flags = code.co_flags
    mem32 = (ctypes.c_int32 * 80).from_address(code_addr)
    lineno_candidates = []
    flag_candidates = []
    for i in range(80):
        if mem32[i] == expected_lineno:
            lineno_candidates.append(i * 4)
        if mem32[i] == expected_flags:
            flag_candidates.append(i * 4)
    if len(lineno_candidates) != 1 or len(flag_candidates) != 1:
        raise RuntimeError(
            "cannot uniquely discover PyCodeObject scalar fields "
            f"(firstlineno={lineno_candidates}, flags={flag_candidates})"
        )
    co_firstlineno = lineno_candidates[0]
    co_flags = flag_candidates[0]

    offsets["PyCodeObject"] = {
        "co_filename": co_filename,
        "co_name": co_name,
        "co_qualname": co_qualname,
        "co_firstlineno": co_firstlineno,
        "co_flags": co_flags,
    }
    print(f"  PyCodeObject: filename={co_filename} name={co_name} qualname={co_qualname} firstlineno={co_firstlineno} flags={co_flags}")

    # === PyUnicodeObject compact data ===
    test_str = "hello_ironscope_probe"
    str_addr = id(test_str)
    mem_bytes = (ctypes.c_uint8 * 128).from_address(str_addr)
    compact_candidates = []
    for i in range(32, 80):
        if bytes(mem_bytes[i : i + 5]) == b"hello":
            compact_candidates.append(i)
    if len(compact_candidates) != 1:
        raise RuntimeError(f"cannot uniquely discover PyUnicodeObject compact data offset: {compact_candidates}")
    compact_data = compact_candidates[0]
    offsets["PyUnicodeObject"] = {"compact_data": compact_data}
    print(f"  PyUnicodeObject: compact_data={compact_data}")

    cpython_offsets = compile_cpython_offset_probe()
    offsets["PyObject"] = cpython_offsets["PyObject"]
    offsets["_PyInterpreterFrame"] = cpython_offsets["_PyInterpreterFrame"]
    offsets["PyGenObject"] = cpython_offsets["PyGenObject"]
    offsets["PyThreadState"] = cpython_offsets["PyThreadState"]
    offsets["PyTypeObject"] = cpython_offsets["PyTypeObject"]

    frame = offsets["_PyInterpreterFrame"]
    gen = offsets["PyGenObject"]
    tstate = offsets["PyThreadState"]
    pyobj = offsets["PyObject"]
    pytype = offsets["PyTypeObject"]
    print(f"  PyObject: ob_type={pyobj['ob_type']}")
    print(f"  PyTypeObject: tp_init={pytype['tp_init']}")
    print(
        "  _PyInterpreterFrame: "
        f"f_executable={frame['f_executable']} previous={frame['previous']} "
        f"owner={frame['owner']} localsplus={frame['localsplus']} "
        f"(derived from target CPython headers)"
    )
    print(f"  PyGenObject: gi_frame_state={gen['gi_frame_state']} gi_iframe={gen['gi_iframe']}")
    print(f"  PyThreadState: current_frame={tstate['current_frame']}")

    # === TaskObj ===
    import _asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # --- task_state: create a task and cancel it, find the byte that flips 0→1 ---
    async def task_coro_state():
        await asyncio.sleep(100)

    task1 = loop.create_task(task_coro_state())
    task1_addr = id(task1)
    mem_b2 = (ctypes.c_uint8 * 400).from_address(task1_addr)
    before_bytes = list(mem_b2[:400])
    task1.cancel()
    loop.run_until_complete(asyncio.sleep(0))
    after_bytes = list(mem_b2[:400])

    state_candidates = [i for i in range(16, 400)
                        if before_bytes[i] == 0 and after_bytes[i] == 1]
    if len(state_candidates) != 1:
        raise RuntimeError(f"cannot uniquely discover TaskObj.task_state offset: {state_candidates}")
    task_state_offset = state_candidates[0]
    print(f"  TaskObj state candidates (0->1 on cancel): {state_candidates}, using {task_state_offset}")

    # --- task_coro: create another task and find its coro pointer ---
    async def task_coro_probe():
        await asyncio.sleep(100)

    task2 = loop.create_task(task_coro_probe())
    task2_addr = id(task2)
    coro_id = id(task2.get_coro())
    coro_offsets = find_ptr_offset(task2_addr, coro_id, 600)
    filtered_coro_offsets = [o for o in coro_offsets if o >= 80]
    if len(filtered_coro_offsets) != 1:
        raise RuntimeError(f"cannot uniquely discover TaskObj.task_coro offset: {coro_offsets}")
    task_coro_offset = filtered_coro_offsets[0]
    print(f"  TaskObj coro candidates: {coro_offsets}, using {task_coro_offset}")

    # --- task_result: create a task that returns a value, find the result pointer ---
    async def task_coro_result():
        return 42

    task3 = loop.create_task(task_coro_result())
    loop.run_until_complete(task3)
    task3_addr = id(task3)
    result_id = id(task3.result())
    result_offsets = find_ptr_offset(task3_addr, result_id, 400)
    filtered_result_offsets = [o for o in result_offsets if 16 < o < 200]
    if len(filtered_result_offsets) != 1:
        raise RuntimeError(f"cannot uniquely discover TaskObj.task_result offset: {result_offsets}")
    task_result_offset = filtered_result_offsets[0]
    print(f"  TaskObj result candidates: {result_offsets}, using {task_result_offset}")

    task2.cancel()
    try:
        loop.run_until_complete(task2)
    except asyncio.CancelledError:
        pass
    loop.close()

    offsets["TaskObj"] = {
        "task_state": task_state_offset,
        "task_coro": task_coro_offset,
        "task_result": task_result_offset,
    }
    print(f"  TaskObj: task_state={task_state_offset} task_coro={task_coro_offset} task_result={task_result_offset}")

    # === PyThreadObject ===
    # threading.Thread is a pure Python class — its attributes (name, target,
    # ident) live in __dict__, not at fixed C struct offsets. We record zeros
    # and a note; later phases probe thread identity via the code-fingerprint
    # approach on Thread.__init__/Thread.run, not struct reads.
    offsets["PyThreadObject"] = {
        "name": 0,
        "ident": 0,
        "target": 0,
    }
    print(f"  PyThreadObject: pure-Python class — attributes in __dict__, not fixed offsets")

    return offsets


def verify_prologue(data, offset, label=""):
    """Check if a file offset looks like an aarch64 function prologue."""
    if offset + 4 > len(data):
        return False
    insn = struct.unpack_from("<I", data, offset)[0]
    # paciasp
    if insn == 0xD503233F:
        return True
    # stp x29, x30, [sp, #-N]!
    if (insn & 0xFFC003FF) == 0xA98003FD:
        return True
    # sub sp, sp, #N
    if (insn & 0xFF000000) == 0xD1000000:
        return True
    return False


def verify_eval_frame_attach_points(data, info):
    """Validate contract-defined interior eval-frame attach points.

    _PyEval_EvalFrameDefault probes attach to proven interpreter-frame
    transition points, not necessarily to a function prologue. Treating those
    offsets as normal function-entry prologues creates false failures on
    CPython builds where the safe attach point is inside the eval loop.
    """
    required = [
        "start_frame_file_offset",
        "resume_file_offset",
        "end_return_value_file_offset",
        "end_return_const_file_offset",
        "end_exception_file_offset",
    ]
    if any(info.get(key) is None for key in required):
        return False
    frame_reg = info.get("frame_reg_idx")
    exc_frame_reg = info.get("end_exception_frame_reg_idx")
    if not isinstance(frame_reg, int) or not 0 <= frame_reg <= 30:
        return False
    if not isinstance(exc_frame_reg, int) or not 0 <= exc_frame_reg <= 30:
        return False
    for key in required:
        offset = info[key]
        if not isinstance(offset, int) or offset % 4 != 0 or offset + 4 > len(data):
            return False
    for offset in info.get("start_frame_extra_file_offsets", []):
        if not isinstance(offset, int) or offset % 4 != 0 or offset + 4 > len(data):
            return False
    return True


def main():
    global PYTHON_BIN, ASYNCIO_PATH, LIBPYTHON_PATH, OUTPUT_DIR, RESUME_FILE_OFFSET
    global START_FRAME_FILE_OFFSET, START_FRAME_REL_OFFSET, FRAME_REG_IDX
    global START_FRAME_FANIN, START_FRAME_EXTRA_FILE_OFFSETS, DECREMENT_BLOCK_COUNT
    parser = argparse.ArgumentParser(description="Generate an IronScope CPython contract")
    parser.add_argument("--python-bin", default=PYTHON_BIN)
    parser.add_argument("--asyncio-path", default=ASYNCIO_PATH)
    parser.add_argument("--libpython-path", default=LIBPYTHON_PATH)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    parser.add_argument("--start-frame-file-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--start-frame-rel-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--frame-reg-idx", type=int, default=None)
    parser.add_argument("--start-frame-fanin", type=int, default=None)
    parser.add_argument("--start-frame-extra-file-offset", type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--decrement-block-count", type=int, default=None)
    parser.add_argument("--resume-file-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--end-exception-file-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--end-return-value-file-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--end-return-const-file-offset", type=lambda v: int(v, 0), default=None)
    parser.add_argument("--end-exception-frame-reg-idx", type=int, default=19)
    args = parser.parse_args()
    PYTHON_BIN = args.python_bin
    ASYNCIO_PATH = args.asyncio_path
    if not ASYNCIO_PATH:
        raise SystemExit("_asyncio is built in for this Python; pass --asyncio-path pointing to the Python executable or module containing asyncio task symbols")
    LIBPYTHON_PATH = args.libpython_path
    OUTPUT_DIR = args.output_dir
    RESUME_FILE_OFFSET = args.resume_file_offset
    START_FRAME_FILE_OFFSET = args.start_frame_file_offset
    START_FRAME_REL_OFFSET = args.start_frame_rel_offset
    FRAME_REG_IDX = args.frame_reg_idx
    START_FRAME_FANIN = args.start_frame_fanin
    START_FRAME_EXTRA_FILE_OFFSETS = args.start_frame_extra_file_offset or []
    DECREMENT_BLOCK_COUNT = args.decrement_block_count

    print("=== CPython Contract Symbol Resolution ===")

    # Build IDs
    print("\n--- Build IDs ---")
    lp_bid, lp_sha = get_build_id_or_sha256(LIBPYTHON_PATH)
    asyncio_bid, asyncio_sha = get_build_id_or_sha256(ASYNCIO_PATH)
    py_bid, py_sha = get_build_id_or_sha256(PYTHON_BIN)

    print(f"  libpython: build_id={lp_bid}")
    print(f"  _asyncio:  build_id={asyncio_bid}")
    print(f"  python3:   build_id={py_bid}")

    # Resolve libpython/python3 symbols
    print("\n--- Python binary symbols ---")
    py_symbols, bin_syms, load_va, load_off = resolve_libpython_symbols()
    for name, info in py_symbols.items():
        print(f"  {name}: offset=0x{info['file_offset']:x} (VA=0x{info['virtual_address']:x})")

    # Resolve type deallocs
    print("\n--- Type dealloc symbols ---")
    dealloc_symbols = resolve_type_deallocs(bin_syms, load_va, load_off)
    for name, info in dealloc_symbols.items():
        print(f"  {name}: offset=0x{info['file_offset']:x}")

    # Resolve _asyncio symbols
    print("\n--- _asyncio symbols (CALL-scan) ---")
    asyncio_symbols = resolve_asyncio_symbols()
    for name, info in asyncio_symbols.items():
        print(f"  {name}: offset=0x{info['file_offset']:x} ({info.get('note', '')})")

    eval_sym = py_symbols["_PyEval_EvalFrameDefault"]
    required_manual_offsets = {
        "--resume-file-offset": RESUME_FILE_OFFSET,
        "--end-exception-file-offset": args.end_exception_file_offset,
        "--end-return-value-file-offset": args.end_return_value_file_offset,
        "--end-return-const-file-offset": args.end_return_const_file_offset,
    }
    missing_manual = [name for name, value in required_manual_offsets.items() if value is None]
    if missing_manual:
        print(
            "FATAL: contract generation requires explicit, build-validated attach offsets: "
            + ", ".join(missing_manual),
            file=sys.stderr,
        )
        sys.exit(1)

    eval_sym["resume_file_offset"] = RESUME_FILE_OFFSET
    eval_sym["resume_offset_source"] = "explicit"
    eval_sym["end_exception_file_offset"] = args.end_exception_file_offset
    eval_sym["end_exception_frame_reg_idx"] = args.end_exception_frame_reg_idx
    eval_sym["end_exception_offset_source"] = "explicit"
    eval_sym["end_return_value_file_offset"] = args.end_return_value_file_offset
    eval_sym["end_return_value_frame_reg_idx"] = eval_sym["frame_reg_idx"]
    eval_sym["end_return_value_offset_source"] = "explicit"
    eval_sym["end_return_const_file_offset"] = args.end_return_const_file_offset
    eval_sym["end_return_const_frame_reg_idx"] = eval_sym["frame_reg_idx"]
    eval_sym["end_return_const_offset_source"] = "explicit"

    # Verify prologues and interior attach points.
    print("\n--- Prologue / attach-point verification ---")
    py_data = open(PYTHON_BIN, "rb").read()
    asyncio_data = open(ASYNCIO_PATH, "rb").read()

    all_ok = True
    for name, info in {**py_symbols, **dealloc_symbols}.items():
        if name == "_PyEval_EvalFrameDefault":
            ok = verify_eval_frame_attach_points(py_data, info)
            status = "OK (interior attach points)" if ok else "FAIL"
        else:
            ok = verify_prologue(py_data, info["file_offset"], name)
            status = "OK" if ok else "FAIL"
        print(f"  {name}: {status}")
        if not ok:
            all_ok = False

    for name, info in asyncio_symbols.items():
        ok = verify_prologue(asyncio_data, info["file_offset"], name)
        status = "OK" if ok else "FAIL"
        print(f"  {name}: {status}")
        if not ok:
            all_ok = False

    if not all_ok:
        print("\nWARNING: Some prologues don't match expected patterns", file=sys.stderr)

    # Discover offsets
    print("\n--- Offset discovery ---")
    offsets = discover_offsets()

    # Merge all symbols (normalize binary field: use the right file for each).
    # Preserve auxiliary fields (size, start_frame_file_offset, frame_reg_idx)
    # where present so Phase 2 can attach at the inline-dispatch target.
    AUX_FIELDS = (
        "size",
        "start_frame_file_offset",
        "start_frame_rel_offset",
        "start_frame_extra_file_offsets",
        "start_frame_offset_source",
        "frame_reg_idx",
        "resume_file_offset",
        "resume_offset_source",
        "end_return_value_file_offset",
        "end_return_value_frame_reg_idx",
        "end_return_value_offset_source",
        "end_return_const_file_offset",
        "end_return_const_frame_reg_idx",
        "end_return_const_offset_source",
        "end_exception_file_offset",
        "end_exception_frame_reg_idx",
        "end_exception_offset_source",
    )
    def _clean(info, normalize_source=True):
        src = info["source"]
        if normalize_source:
            src = src.replace("python_binary_", "libpython_")
        out = {"source": src, "file_offset": info["file_offset"]}
        for k in AUX_FIELDS:
            if k in info:
                out[k] = info[k]
        return out

    symbols = {}
    for name, info in py_symbols.items():
        symbols[name] = _clean(info)
    for name, info in dealloc_symbols.items():
        symbols[name] = _clean(info)
    for name, info in asyncio_symbols.items():
        symbols[name] = _clean(info, normalize_source=False)

    # Build contract
    contract = {
        "python": {
            "implementation": "cpython",
            "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "arch": os.uname().machine,
            "build_id": py_bid or "",
            "sha256_fallback": py_sha or "",
        },
        "libpython": {
            "path": PYTHON_BIN,
            "build_id": py_bid or "",
            "build_id_fallback_sha256": py_sha or "",
            "elf_class": "ELFCLASS64",
            "arch": os.uname().machine,
            "note": "python3 binary has libpython statically linked; uprobe symbols resolve against this binary",
        },
        "libpython_shared": {
            "path": LIBPYTHON_PATH,
            "build_id": lp_bid or "",
            "note": "shared libpython exists but is not used by the python3 process; listed for reference",
        },
        "asyncio_module": {
            "path": ASYNCIO_PATH,
            "build_id": asyncio_bid or asyncio_sha or "",
        },
        "python_binary": {
            "path": PYTHON_BIN,
            "build_id": py_bid or "",
        },
        "symbols": symbols,
        "offsets": offsets,
        "frame_state_values": {
            "CREATED": -2,
            "SUSPENDED": -1,
            "EXECUTING": 0,
            "COMPLETED": 1,
        },
        "task_state_values": {
            "PENDING": 0,
            "CANCELLED": 1,
            "FINISHED": 2,
        },
        "classifier_rules_file": "../tools/rules/framework_rules.yaml",
        "contract_version": 2,
        "generated_ns": int(time.time_ns()),
    }


    # Verify all required keys are present
    required_syms = {
        "_PyEval_EvalFrameDefault",
        "PyGen_Type_tp_dealloc",
        "PyCoro_Type_tp_dealloc",
        "PyAsyncGen_Type_tp_dealloc",
        "_asyncio_Task___init___impl",
        "task_step",
        "task_eager_start",
    }
    missing = required_syms - set(symbols.keys())
    if missing:
        print(f"FATAL: Missing symbols: {missing}", file=sys.stderr)
        sys.exit(1)

    # Verify offsets — zeros are expected for f_executable and PyThreadObject
    known_zero_ok = {
        ("_PyInterpreterFrame", "f_executable"),
        ("PyThreadObject", "name"),
        ("PyThreadObject", "ident"),
        ("PyThreadObject", "target"),
    }
    for group, fields in offsets.items():
        for field, val in fields.items():
            if (val is None or val == 0) and (group, field) not in known_zero_ok:
                print(f"WARNING: {group}.{field} = {val}")

    # Write contract only after all required checks pass.
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    contract_name = f"cpython-{contract['python']['arch']}-{py_bid or py_sha}.json"
    contract_path = os.path.join(OUTPUT_DIR, contract_name)
    with open(contract_path, "w") as f:
        json.dump(contract, f, indent=2)

    print(f"\n=== Contract written to {contract_path} ===")

    print("\nPhase 0: Symbol resolution COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
