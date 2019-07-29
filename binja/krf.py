import logging

log = logging.getLogger(__name__)

import binaryninja as bn
from binaryninja.mediumlevelil import MediumLevelILOperation


class KRFAnalysis(object):
    def __init__(self, filename):
        self.filename = filename
        self.bv = bn.BinaryViewType["ELF"].open(filename)
        log.debug("Running analysis")
        self.bv.update_analysis_and_wait()
        log.debug("Analysis finished")

    def checkFunction(self, func, call, tainted):
        visited_instructions = set()
        var_stack = []
        tainted_args = []
        for i in tainted:  # Only if in tainted args
            if call.params[i].operation == MediumLevelILOperation.MLIL_VAR_SSA:
                var_stack.append(call.params[i].src)

        while len(var_stack) > 0:
            var = var_stack.pop()
            if var in visited_instructions:
                continue
            else:
                visited_instructions.add(var)
            try:
                decl = func.get_ssa_var_definition(var)
            except AttributeError:
                print("Failed on var", var, "...trying normal variable def")
                decl = func[func.get_var_definitions(var)[0]]
            if decl is None:  # It's probably an argument
                # print("Argument", var.var.name, "tainted from function call")
                for i, param in enumerate(func.source_function.function_type.parameters):
                    if param.name == var.var.name:
                        # print("  Argument #:", i)
                        tainted_args.append(i)
                continue
            if decl.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                if decl.dest.value.is_constant:
                    func_called = self.bv.get_function_at(decl.dest.value.value)
                    print(
                        "Tainted by call to", func_called.name, "(", hex(decl.dest.value.value), ")"
                    )
                else:
                    print("Tainted by indirect call at instruction", hex(decl.address))
                continue
            # Otherwise, recurse into it's parents
            for v in decl.vars_read:
                var_stack.append(v)

        return tainted_args

    def run(self, *rips, numArgs=None, startAddr=0, taintedArgs=None):
        # Pass in instruction pointers, starting from the lowest frame and going up
        # numArgs in the number of args passed to the lowest frame, needed for libc
        # startAddr is subtracted from the rips
        index = 0
        if taintedArgs is not None:
            numArgs = 1  # To pass check in while loop
        elif numArgs is not None:
            taintedArgs = range(numArgs)
        else:
            taintedArgs = [1]  # to pass while loop check

        while ((len(rips) - index) > 1) and len(taintedArgs) > 0:
            try:
                func = self.bv.get_functions_containing(rips[index + 1] - startAddr)[
                    0
                ].medium_level_il
                call = func[func.get_instruction_start(rips[index + 1] - startAddr) - 1].ssa_form
                func = func.ssa_form
                func2 = self.bv.get_functions_containing(rips[index] - startAddr)[0]
                func2_ptr = func2.start  # ptr to front
                print("Searching through function", func.source_function.name, "for", func2.name)
                print("call:", call)
            except AttributeError:
                raise Exception("Could not find function containing {:x}".format(inst_ptr))

            if numArgs is None:  # Add all parameters if not set (need to be set for libc stuff)
                taintedArgs = range(len(func2.function_type.parameters))
            taintedArgs = self.checkFunction(func, call, taintedArgs)
            # print(taintedArgs)
            index += 1

        if len(taintedArgs) > 0:
            print("Parameters to top level function tainted:", taintedArgs)
        else:
            print("All paths checked")
