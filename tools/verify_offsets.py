#!/usr/bin/env python3
"""
Verify CPython runtime offsets from an IronScope contract.
Must print 'OFFSETS_VERIFIED' on success.
"""
import argparse
import asyncio
import ctypes
import glob
import json
import os
import sys
import types

ERRORS = 0

def check(label, expected, actual):
    global ERRORS
    if expected == actual:
        print(f"OFFSET CONFIRMED: {label} at {expected}")
    else:
        print(f"OFFSET MISMATCH: {label} expected {expected}, got {actual}")
        ERRORS += 1

def find_offset(obj_addr, target_value, max_range=300):
    mem = (ctypes.c_uint64 * (max_range // 8)).from_address(obj_addr)
    return [i * 8 for i, v in enumerate(mem) if v == target_value]


def default_contract_path():
    root = os.path.dirname(__file__)
    candidates = sorted(glob.glob(os.path.join(root, "python-contracts", "cpython-3.12.3-*.json")))
    if candidates:
        return candidates[0]
    raise SystemExit("no packaged CPython contract found; pass --contract")


parser = argparse.ArgumentParser(description="Verify IronScope CPython contract offsets in this interpreter")
parser.add_argument("--contract", default=default_contract_path(), help="contract JSON to verify")
args = parser.parse_args()

with open(args.contract) as f:
    contract = json.load(f)
offsets = contract["offsets"]

# === PyCodeObject ===
# Use a method so co_qualname ("_Ctx._m") differs from co_name ("_m")
class _Ctx:
    async def _m(self): pass

code = _Ctx._m.__code__
code_addr = id(code)

fn_offsets = find_offset(code_addr, id(code.co_filename))
nm_offsets = find_offset(code_addr, id(code.co_name))
qn_offsets = find_offset(code_addr, id(code.co_qualname))

expected = offsets["PyCodeObject"]
check("co_filename", expected["co_filename"],
      fn_offsets[0] if fn_offsets else -1)
check("co_name", expected["co_name"],
      nm_offsets[0] if nm_offsets else -1)
check("co_qualname", expected["co_qualname"],
      qn_offsets[0] if qn_offsets else -1)

# co_firstlineno
mem32 = (ctypes.c_int32 * 80).from_address(code_addr)
lineno = code.co_firstlineno
actual_lineno_off = -1
for i in range(80):
    if mem32[i] == lineno:
        actual_lineno_off = i * 4
        break
check("co_firstlineno", expected["co_firstlineno"], actual_lineno_off)

# === PyUnicodeObject ===
test_str = "hello_ironscope_verify"
str_addr = id(test_str)
mem_bytes = (ctypes.c_uint8 * 128).from_address(str_addr)
actual_data_off = -1
for i in range(32, 80):
    if bytes(mem_bytes[i:i+5]) == b"hello":
        actual_data_off = i
        break
check("unicode_data", offsets["PyUnicodeObject"]["compact_data"], actual_data_off)

# === PyGenObject ===
# Use types.coroutine to avoid any asyncio event loop dependency
@types.coroutine
def _yield_once():
    yield

async def target_coro():
    await _yield_once()

c = target_coro()
coro_addr = id(c)
code_addr2 = id(target_coro.__code__)

iframe_offsets = find_offset(coro_addr, code_addr2, 400)
gi_iframe_actual = min((o for o in iframe_offsets if o >= 64), default=-1)
check("gi_iframe", offsets["PyGenObject"]["gi_iframe"], gi_iframe_actual)

# gi_frame_state: verify via state transitions (CREATED → SUSPENDED → COMPLETED)
mem_b = (ctypes.c_int8 * 200).from_address(coro_addr)
before = list(mem_b[60:80])

try:
    c.send(None)
except StopIteration:
    pass

after_suspend = list(mem_b[60:80])

try:
    c.send(None)
except StopIteration:
    pass

after_complete = list(mem_b[60:80])
c.close()

gi_fs_actual = -1
for i, (a, b, d) in enumerate(zip(before, after_suspend, after_complete)):
    idx = i + 60
    # CREATED(-2) → SUSPENDED(-1) → COMPLETED(1) or CLEARED(4)
    if a == -2 and b == -1 and d > 0:
        gi_fs_actual = idx
        break
check("gi_frame_state", offsets["PyGenObject"]["gi_frame_state"], gi_fs_actual)

# === TaskObj ===
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# task_state: verify by cancel
async def ts_coro():
    await asyncio.sleep(100)

task1 = loop.create_task(ts_coro())
task1_addr = id(task1)
mem_t = (ctypes.c_uint8 * 400).from_address(task1_addr)
before_t = list(mem_t[:400])
task1.cancel()
loop.run_until_complete(asyncio.sleep(0))
after_t = list(mem_t[:400])

ts_actual = -1
state_candidates = [i for i in range(16, 400) if before_t[i] == 0 and after_t[i] == 1]
if state_candidates:
    ts_actual = min(state_candidates, key=lambda x: abs(x - offsets["TaskObj"]["task_state"]))
check("task_state", offsets["TaskObj"]["task_state"], ts_actual)

# task_coro: verify pointer
async def tc_coro():
    await asyncio.sleep(100)

task2 = loop.create_task(tc_coro())
task2_addr = id(task2)
coro_id = id(task2.get_coro())
coro_off = find_offset(task2_addr, coro_id, 600)
tc_actual = min((o for o in coro_off if o >= 80), default=-1)
check("task_coro", offsets["TaskObj"]["task_coro"], tc_actual)

# task_result: verify by completing a task
async def tr_coro():
    return 42

task3 = loop.create_task(tr_coro())
loop.run_until_complete(task3)
task3_addr = id(task3)
result_id = id(task3.result())
result_off = find_offset(task3_addr, result_id, 400)
tr_actual = min((o for o in result_off if 16 < o < 200), default=-1)
check("task_result", offsets["TaskObj"]["task_result"], tr_actual)

task2.cancel()
try:
    loop.run_until_complete(task2)
except asyncio.CancelledError:
    pass
loop.close()

# === frame_state_values ===
fs_vals = contract["frame_state_values"]
assert fs_vals["CREATED"] == -2, f"FRAME_CREATED should be -2, got {fs_vals['CREATED']}"
assert fs_vals["SUSPENDED"] == -1, f"FRAME_SUSPENDED should be -1, got {fs_vals['SUSPENDED']}"
assert fs_vals["EXECUTING"] == 0, f"FRAME_EXECUTING should be 0, got {fs_vals['EXECUTING']}"
assert fs_vals["COMPLETED"] == 1, f"FRAME_COMPLETED should be 1, got {fs_vals['COMPLETED']}"
print("OFFSET CONFIRMED: frame_state_values match CPython 3.12 spec")

# === task_state_values ===
ts_vals = contract["task_state_values"]
assert ts_vals["PENDING"] == 0
assert ts_vals["CANCELLED"] == 1
assert ts_vals["FINISHED"] == 2
print("OFFSET CONFIRMED: task_state_values match _asynciomodule.c spec")

# === Summary ===
print(f"\nOffset verification complete. Errors: {ERRORS}")
if ERRORS == 0:
    print("OFFSETS_VERIFIED")
else:
    sys.exit(1)
