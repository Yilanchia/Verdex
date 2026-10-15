# Verdex IDA headless decompile dumper. Runs inside IDA's bundled Python via
# `idat -A -S"ida_dump.py <out.json> [symbol]"`. Read-only: analyzes the target,
# never executes it. Emits JSON {hexrays, functions:[{name, ea, pseudocode|error}]}.
import json
import idc
import idautils
import ida_funcs
import ida_hexrays
import ida_auto
import ida_pro

ida_auto.auto_wait()

argv = idc.ARGV
out_path = argv[1] if len(argv) > 1 else "verdex_decompile.json"
target_symbol = argv[2] if len(argv) > 2 else None

result = {"hexrays": False, "functions": []}

if not ida_hexrays.init_hexrays_plugin():
    result["error"] = "hexrays plugin unavailable"
else:
    result["hexrays"] = True
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if target_symbol and name != target_symbol:
            continue
        entry = {"name": name, "ea": hex(ea)}
        try:
            entry["pseudocode"] = str(ida_hexrays.decompile(ea))
        except Exception as exc:
            entry["error"] = str(exc)
        result["functions"].append(entry)
    if target_symbol and not result["functions"]:
        result["error"] = "symbol not found: " + str(target_symbol)

with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle, ensure_ascii=False, indent=2)

ida_pro.qexit(0)
