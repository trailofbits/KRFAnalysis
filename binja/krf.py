import logging

log = logging.getLogger(__name__)

import binaryninja as bn
from binaryninja.mediumlevelil import MediumLevelILOperation


class KRFAnalysis:
    def __init__(self, filename):
        self.filename = filename
        self.bv = bn.BinaryViewType["ELF"].open(filename)
        log.debug("Running analysis")
        self.bv.update_analysis_and_wait()
        log.debug("Analysis finished")

    def getMLILforInst(self, inst_ptr, func):  # Heuristic to get MLIL for instruction
        inst = func.get_instruction_start(inst_ptr)  # index of inst
        while inst is None:  # Keep going forward an inst, since they collapse forward
            inst_ptr += self.bv.get_instruction_length(inst_ptr)
            inst = func.get_instruction_start(inst_ptr)
        return func[inst].ssa_form

    def getMLILforCall(self, inst_ptr, func):  # Get it when its a call
        for il in func.instructions:
            if il.operation == MediumLevelILOperation.MLIL_CALL and (
                il.address + self.bv.get_instruction_length(il.address) == inst_ptr
            ):
                return il.ssa_form

    def checkFunction(self, func, call, tainted, frameZero=False):
        visited_instructions = set()
        var_stack = []
        tainted_args = []
        # Set up the intially tainted vars
        if frameZero:
            for v in call.vars_read:
                var_stack.append(v)
        else:
            for i in tainted:  # Only if in tainted args
                try:
                    if call.params[i].operation == MediumLevelILOperation.MLIL_VAR_SSA:
                        var_stack.append(call.params[i].src)
                except IndexError:
                    log.warning(
                        "Calling convention error: expected an argument #"
                        + str(i)
                        + " but there are only "
                        + str(len(call.params))
                        + " arguments. Ignoring."
                    )
        # Continously run analysis while elements are in the stack
        while len(var_stack) > 0:
            var = var_stack.pop()
            if var in visited_instructions:
                continue
            else:
                visited_instructions.add(var)

            # Get variable declaration
            try:
                decl = func.get_ssa_var_definition(var)
            except AttributeError:
                log.warning("Failed on var " + str(var) + " ...trying normal variable def")
                decl = func[func.get_var_definitions(var)[0]]

            # Check if its an argument
            if decl is None:  # It's probably an argument
                log.debug("Argument " + var.var.name + " tainted from function call")
                for i, param in enumerate(func.source_function.function_type.parameters):
                    if param.name == var.var.name:
                        tainted_args.append(i)
                continue

            # Check if its a function call
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

    def run(self, *rips, numArgs=None, startAddr=0, taintedArgs=None, frameZero=False):
        # Pass in instruction pointers, starting from the lowest frame and going up
        # numArgs in the number of args passed to the lowest frame, needed for libc
        # startAddr is subtracted from the rips
        index = 0
        if taintedArgs is not None:
            numArgs = 1  # To pass check in while loop
        elif numArgs is not None:
            taintedArgs = range(numArgs)
        else:
            taintedArgs = [1]  # to pass while loop check, gets overwritten later

        while index < len(rips) and len(taintedArgs) > 0:
            inst_ptr = rips[index] - startAddr
            try:
                func = self.bv.get_functions_containing(inst_ptr)[
                    0
                ].medium_level_il  # Containing function
            except AttributeError:
                raise Exception("Could not find function containing {:x}".format(inst_ptr))

            if not frameZero or index != 0:
                call = self.getMLILforCall(
                    inst_ptr, func
                )  # Get address of instruction we are actually interested in
            else:
                call = self.getMLILforInst(inst_ptr, func)

            func = func.ssa_form

            print("Searching through function", func.source_function.name)
            log.debug("call: " + str(call))

            if numArgs is None and not frameZero:  # Add all parameters if not manually set
                taintedArgs = range(len(call.params))
            taintedArgs = self.checkFunction(
                func, call, taintedArgs, frameZero=(frameZero if index == 0 else False)
            )
            log.debug(taintedArgs)
            index += 1

        if len(taintedArgs) > 0:
            print("Parameters to top level function tainted:", taintedArgs)
        else:
            print("All paths checked")

        return taintedArgs
