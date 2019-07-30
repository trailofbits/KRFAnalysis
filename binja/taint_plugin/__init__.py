from binaryninja import *


def do_nothing(bv, inst):
    inst = inst.ssa_form
    visited_instructions = set()
    var_stack = []
    tainted_args = []
    for i in inst.vars_read:
        var_stack.append(i)

    func = inst.function
    func.source_function.set_user_instr_highlight(
        inst.address, HighlightStandardColor.BlueHighlightColor
    )
    while len(var_stack) > 0:
        var = var_stack.pop()
        if var in visited_instructions:
            continue
        else:
            visited_instructions.add(var)
        try:
            decl = func.get_ssa_var_definition(var)
        except AttributeError:
            print("Failed on var " + str(var) + " ...trying normal variable def")
            decl = func[func.get_var_definitions(var)[0]]
        if decl is None:  # It's probably an argument
            tainted_args.append(var.var.name)
            print("Argument", var.var.name, "tainted from function call")
            continue
        if decl.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            func.source_function.set_user_instr_highlight(
                decl.address, HighlightStandardColor.RedHighlightColor
            )
            if decl.dest.value.is_constant:
                func_called = bv.get_function_at(decl.dest.value.value)
                print("Tainted by call to", func_called.name, "(", hex(decl.dest.value.value), ")")
            else:
                print("Tainted by indirect call at instruction", hex(decl.address))
            continue
        # Otherwise, recurse into it's parents
        for v in decl.vars_read:
            var_stack.append(v)

    if len(tainted_args) == 0:
        message = ""
    else:
        message = "Tainted parameters are: " + ", ".join(tainted_args)
    show_message_box(
        "Reverse Taint",
        "Finished analysis. Any function calls that are sources are highlighted red. " + message,
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon,
    )


PluginCommand.register_for_medium_level_il_instruction(
    "Reverse Taint Analysis", "Traces back the sources of an instruction", do_nothing
)
