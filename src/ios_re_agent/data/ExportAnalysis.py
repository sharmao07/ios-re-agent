# Ghidra headless post-script. Kept compatible with Ghidra's Jython 2.7 runtime.
# @category iOS-RE Agent
# @runtime Jython
import json

MAX_FUNCTIONS = 800
MAX_STRINGS = 1500
MAX_PSEUDOCODE_PER_FUNCTION = 12000
MAX_TOTAL_PSEUDOCODE = 3000000
MAX_INSTRUCTIONS_PER_FUNCTION = 2500


def safe_text(value, limit=1000):
    try:
        text = str(value)
    except Exception:
        text = ""
    return text[:limit]


def main():
    args = getScriptArgs()
    if not args:
        raise Exception("Expected output JSON path as the first script argument")
    output_path = args[0]
    program = currentProgram
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    reference_manager = program.getReferenceManager()
    decompiler = None
    functions = []
    total_pseudocode = 0

    from ghidra.app.decompiler import DecompInterface
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    iterator = function_manager.getFunctions(True)
    all_functions = []
    while iterator.hasNext():
        function = iterator.next()
        if not function.isExternal():
            all_functions.append(function)
    for function in all_functions[:MAX_FUNCTIONS]:
        if monitor.isCancelled():
            break
        item = {
            "name": safe_text(function.getName(), 300),
            "entry_point": str(function.getEntryPoint()),
            "signature": safe_text(function.getPrototypeString(False, True), 1000),
            "body_address_count": int(function.getBody().getNumAddresses()),
            "pseudocode": None,
            "callers": [],
            "callees": [],
        }
        # Collect a bounded set of direct call references from this function.
        try:
            instructions = listing.getInstructions(function.getBody(), True)
            instruction_count = 0
            callees = set()
            while instructions.hasNext() and instruction_count < MAX_INSTRUCTIONS_PER_FUNCTION:
                instruction = instructions.next()
                instruction_count += 1
                refs = reference_manager.getReferencesFrom(instruction.getAddress())
                for reference in refs:
                    if reference.getReferenceType().isCall():
                        callee = function_manager.getFunctionContaining(reference.getToAddress())
                        if callee is not None:
                            callees.add(safe_text(callee.getName(), 300))
            item["callees"] = sorted(callees)[:100]
        except Exception:
            pass
        try:
            result = decompiler.decompileFunction(function, 30, monitor)
            if result is not None and result.decompileCompleted() and result.getDecompiledFunction() is not None:
                code = safe_text(result.getDecompiledFunction().getC(), MAX_PSEUDOCODE_PER_FUNCTION)
                available = max(0, MAX_TOTAL_PSEUDOCODE - total_pseudocode)
                if available > 0:
                    code = code[:available]
                    item["pseudocode"] = code
                    total_pseudocode += len(code)
        except Exception:
            item["decompile_error"] = "Ghidra could not decompile this function"
        functions.append(item)

    # Build reverse caller references from the function-to-callee edges collected above.
    callers_by_name = {}
    for caller in functions:
        for callee_name in caller.get("callees", []):
            callers_by_name.setdefault(callee_name, set()).add(caller["name"])
    for function in functions:
        function["callers"] = sorted(callers_by_name.get(function["name"], set()))[:100]

    # Recover likely C/Objective-C/Swift string data with addresses and evidence source.
    strings = []
    try:
        data_iterator = listing.getDefinedData(True)
        while data_iterator.hasNext() and len(strings) < MAX_STRINGS:
            data = data_iterator.next()
            if data is None or data.getDataType() is None:
                continue
            type_name = safe_text(data.getDataType().getName(), 100).lower()
            if "string" not in type_name:
                continue
            value = safe_text(data.getValue(), 1000)
            if len(value.strip()) >= 4:
                strings.append({"address": str(data.getAddress()), "value": value, "data_type": type_name})
    except Exception:
        pass

    decompiled_count = len([item for item in functions if item.get("pseudocode")])
    payload = {
        "format_version": "1.0",
        "program_name": safe_text(program.getName(), 300),
        "language": safe_text(program.getLanguageID(), 100),
        "compiler_spec": safe_text(program.getCompilerSpec().getCompilerSpecID(), 100),
        "function_count": len(all_functions),
        "functions_exported": len(functions),
        "decompiled_count": decompiled_count,
        "string_count": len(strings),
        "functions": functions,
        "strings": strings,
        "limits": {
            "max_functions": MAX_FUNCTIONS,
            "max_strings": MAX_STRINGS,
            "max_pseudocode_characters": MAX_TOTAL_PSEUDOCODE,
            "max_instructions_per_function_for_calls": MAX_INSTRUCTIONS_PER_FUNCTION,
        },
    }
    output = open(output_path, "w")
    try:
        json.dump(payload, output, indent=2, sort_keys=True)
        output.write("\n")
    finally:
        output.close()
    decompiler.dispose()


main()
