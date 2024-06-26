from llvmlite import ir
import xml.etree.ElementTree as et

int64 = function_names = registers = functions = uniques = internal_functions = \
    memory = pointers = None


def reset_globals():
    global int64, function_names, registers, functions, uniques, internal_functions, memory, pointers

    int64 = ir.IntType(64)
    function_names = []
    registers, functions, uniques, internal_functions, memory = {}, {}, {}, {}, {}
    pointers = []


def lift(filename):
    global pointers

    reset_globals()

    root = et.parse(filename).getroot()
    module = ir.Module(name="lifted")

    for register in root.find('globals').findall('register'):
        register_name = register.get('name')
        register_width = 8 * int(register.get('size'))
        register_flags = int(register.get('flags'))

        # Determine register type based on the flags and width
        if register_flags & 128:  # Register.TYPE_VECTOR
            register_type = ir.VectorType(ir.IntType(1), register_width)
        else:
            register_type = ir.IntType(register_width)

        # Determine whether the register always contains a pointer, and if so,
        # add it to a list of pointer registers.
        # TODO: Is this distinction between 'pointer registers' and normal
        #       registers really necessary for correct translation to LLVM IR?
        # HACK: The 'or ...' clause is a workaround for: https://github.com/NationalSecurityAgency/ghidra/issues/5415
        if register_flags & (1 | 2 | 4) or register_name in {"RSP", "ESP", "RBP",
                                                             "EBP"}:  # Register.TYPE_FP | Register.TYPE_SP | Register.TYPE_PC
            pointers.append(register_name)
            register_type = ir.PointerType(register_type)

        if register_name in pointers:
            # Not sure why this is 8...
            register_type = ir.PointerType(ir.IntType(8))
        else:
            register_type = ir.IntType(register_width)

        var = ir.GlobalVariable(module, register_type, register_name)
        var.initializer = ir.Constant(register_type, None)
        var.linkage = 'internal'
        registers[register_name] = var

    for memory_location in root.find('memory').findall('memory'):
        var = ir.GlobalVariable(module, ir.IntType(8 * int(memory_location.get('size'))), memory_location.get('name'))
        var.initializer = ir.Constant(ir.IntType(8 * int(memory_location.get('size'))), None)
        var.linkage = 'internal'
        memory[memory_location.get('name')] = var

    for name in ("intra_function_branch", "call_indirect", "special_subpiece", "bit_extraction"):
        internal_functions[name] = ir.Function(module, ir.FunctionType(ir.VoidType(), []), name)

    for function in root.findall('function'):
        func_name = function.get('name')

        if func_name in function_names:
            x = 0
            while (name := f"{func_name}_{x}") in function_names:
                x += 1
        else:
            name = func_name

        function_names.append(name)
        address = function.get('address')
        functions[address] = (build_function(name, module), function)

    for address in functions:
        populate_func(*functions[address])

    return module


def populate_func(ir_func, function):
    builders, blocks = build_cfg(function, ir_func)
    if blocks == {}:
        return
    populate_cfg(function, builders, blocks)


def build_function(name, module):
    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, name)
    return ir_func


def build_cfg(function, ir_func):
    builders, blocks = {}, {}
    instructions = function.find("instructions")
    if instructions:
        block = ir_func.append_basic_block("entry")
        blocks["entry"] = block
        builders["entry"] = ir.IRBuilder(block)
        for instruction in instructions:
            address = instruction.find("address").text
            block = ir_func.append_basic_block(address)
            blocks[address] = block
            builders[address] = ir.IRBuilder(block)
    return builders, blocks

def build_cmpxchg(builder, instruction, pcode):
    # TODO - Implement p-code relative branching
    print("CMPXCHG instruction!")
    # find relative pcode
    # get current p code index for instruction:
    current_index = int(pcode.tag.replace("pcode_", ""))
    # get offset value from constant
    # offset = int(input.replace("0x", ""))
    # Hexadecimal address offset
    offset = int(input, 16)
    print("offset: " + str(offset))
    # get jump pcode index:
    pcode_jump_index = current_index + offset
    # get branch address from p-code at offset index
    pcode_jump = instruction.find("pcodes")[pcode_jump_index]

    # ptr ist first variable in instruction
    # setup ptr: right now: R12 - TODO
    # LOAD WITH 2 INPUTS - output = *[input0]input1;
    # IF input0 exists -> load from address input0 with offset input1
    load_pcode = instruction.find("pcodes")[0]
    ptr = load_pcode.find("input_1")
    # load_pcode.find("input_1").text = R12
    # load_pcode.find("input_1").get("storage") = register
    input_1 = load_pcode.find("input_1")
    # fetch_input_varnode(builder, input1)
    # return builder.load(registers[name.text])
    # ABER ICH WILL registers[input0 + input1]
    # > registers[0x1b1 + *R12]
    # INHALT von R12: %".19008" = load i64, i64* @"R12"
    # load value from register -> offset
    # load from memory address[input0 + offset]
    # registers[instruction.find("pcodes")[0].find("input_1").text]

    # setup val:
    # find cbranch pcode: pcode_jump
    # this should be COPY
    # find input0
    # this is val
    val = pcode_jump.find("input0")

    # setup cmp:
    cmp = "TODO"
    # find comparison operation that has output ZF
    # last operation that sets up ZF bevor CBRANCH will have the comparison
    # pcode 4

    # Use pcode implementation to run needed pcodes through existing code
    # pcode4 is compare operation
    # pcode 1 loads pointer value
    # TODO

    # TODO WHAT IS ORDERING
    # Ordering is optional
    # https://llvmlite.readthedocs.io/en/latest/user-guide/ir/ir-builder.html
    # TODO - FINAL VALUES
    ##############################################

    pcode = instruction.find("pcodes")[0]
    # todo - R12 + offset not just R12
    ptr = pcode.find("input_1") # this is ptr R12

    pcode = instruction.find("pcodes")[14]
    val = pcode.find("input_0")
    ##############################################
    # COMPARISON: x = *ptr[R12+offset]
    # a = RAX < x
    #
    # Go through pcodes:

    # LOAD 0x1b1, R12 - u_5500:8
    pcode = instruction.find("pcodes")[0]
    input_1 = pcode.find("input_1") # THIS IS R12
    output = pcode.find("output")
    load_ptr = fetch_input_varnode(builder, input_1)
    if input_1.get("storage") == "register":
        if input_1.text in pointers:
            # Don't load from the register, but load from the value
            # contained in the register
            load_ptr = builder.gep(load_ptr, [ir.Constant(int64, 0)])

        if not load_ptr.type.is_pointer:
            # LLVM doesn't know this is a pointer yet...
            # Make it point to the output type
            output_size = 8 * int(output.get("size"))
            load_ptr = builder.inttoptr(load_ptr, ir.PointerType(ir.IntType(output_size)))

        result = builder.load(load_ptr) # value of ptr[R12] -> value of old
        update_output(builder, output, result)
    else:
        raise NotImplementedError(
            f"INCORRECT LOAD IN CMPXCHG Instruction: {et.tostring(pcode)}")
    # COPY u_5500:8 - u_ca400:8
    # INT_LESS RAX, u_ca400:8 - CF
    # INT_SBORROW RAX, u_ca400:8 - OF
    # INT_SUB RAX, u_ca400:8 - u_ca500:8
    # INT_SLESS u_ca500:8, 0x0 - SF
    # INT_EQUAL u_ca500:8, 0x0 - ZF
    # INT_AND u_ca500:8, 0xff - u_13400:8
    # POPCOUNT u_13400:8 - u_13480:1
    # INT_AND u_13480:1, 0x1 - u_13500:1
    # INT_EQUAL u_13500:1, 0x0 - PF
    # CBRANCH 0x3, ZF -
    # COPY u_ca400:8 - RAX
    # BRANCH 0x3 -
    # COPY RDI - u_5500:8
    # STORE 0x1b1, R12, u_5500:8 -



    return ptr, val, cmp

# noinspection DuplicatedCode
def populate_cfg(function, builders, blocks):
    builder = builders["entry"]

    stack_size = 10 * 1024 * 1024
    stack = builder.alloca(ir.IntType(8), stack_size, name="stack")
    stack_top = builder.gep(stack, [ir.Constant(int64, stack_size - 8)], name="stack_top")
    try:
        builder.store(stack_top, registers["RSP"])
    except:
        pass
        # print("no RSP registers.")
    builder.branch(list(blocks.values())[1])

    for block_iterator, instruction in enumerate(function.find("instructions"), start=2):


        address = instruction.find("address").text
        builder = builders.get(address, builder)

        relative_branch = {}
        no_branch = True

        relative_branch_index = 0
        close_branch = False

        for pcode in instruction.find("pcodes"):
            mnemonic = pcode.find("name")

            if relative_branch_index > 0:
                relative_branch_index = relative_branch_index - 1
                if relative_branch_index == 0:
                    close_branch = True
                    print("found instruction to jump to.")
                    # todo - check instruction still in same block!
                    relative_branch['instruction_count'] = len(list(blocks.values())[block_iterator - 1].instructions)

                else:
                    print("Calculating relative branching address. Index at: " + str(relative_branch_index) + " - " + mnemonic.text)
            # Block iterator 2128 -> BRANCH RELATIVE - address: 10000543c
            # list(blocks.values())[2128 - 1]
            # see instructions
            # list(blocks.values())[2128 - 1].instructions
            # find instruction for branch offset pcode
            # 30 instructions in current block
            try:
                if mnemonic.text == "COPY":
                    source = fetch_input_varnode(builder, pcode.find("input_0"))
                    update_output(builder, pcode.find("output"), source)

                elif mnemonic.text == "CALLOTHER":
                    raise NotImplementedError(f"CALLOVER pcode at {address} needs to be implemented.")
                elif mnemonic.text == "LOAD":
                    input_1 = pcode.find("input_1")
                    output = pcode.find("output")

                    # TODO - implement input_0
                    input_0 = pcode.find("input_0")

                    load_ptr = fetch_input_varnode(builder, input_1)
                    if input_0 != None:
                        # TODO
                        pass
                        # print("UNIMPLEMENTED LOAD: " + address + " - " + str(pcode))
                        # load_ptr = fetch_input_varnode(builder, input_0)
                        # load_ptr = builder.gep(load_ptr, [ir.Constant(int64, input_1)])
                    if input_1.get("storage") == "unique" and output.get("storage") == "unique" or output.get("storage") == "register":
                        # This is incorrect. This is treating it as a copy, should load the memory address in the input 1
                        update_output(builder, output, load_ptr)
                    elif input_1.get("storage") == "register":
                        if input_1.text in pointers:
                            # Don't load from the register, but load from the value
                            # contained in the register
                            load_ptr = builder.gep(load_ptr, [ir.Constant(int64, 0)])

                        if not load_ptr.type.is_pointer:
                            # LLVM doesn't know this is a pointer yet...
                            # Make it point to the output type
                            output_size = 8 * int(output.get("size"))
                            load_ptr = builder.inttoptr(load_ptr, ir.PointerType(ir.IntType(output_size)))

                        result = builder.load(load_ptr)
                        update_output(builder, output, result)
                    else:
                        raise NotImplementedError(
                            f"Weird and not implemented LOAD, arising from PCODE: {et.tostring(pcode)}")

                elif mnemonic.text == "STORE":
                    input_1 = pcode.find("input_1")  # store location
                    input_2 = pcode.find("input_2")  # store value
                    rhs = fetch_input_varnode(builder, input_2)
                    lhs = fetch_output_varnode(input_1)
                    if not lhs.type.is_pointer:
                        # LLVM doesn't know this is a pointer yet...
                        # Make it point to the storage value type
                        store_size = 8 * int(input_2.get("size"))
                        lhs = builder.inttoptr(lhs, ir.PointerType(ir.IntType(store_size)))
                    lhs2 = builder.gep(lhs, [ir.Constant(int64, 0)])
                    if lhs2.type != rhs.type.as_pointer():
                        lhs2 = builder.bitcast(lhs2, rhs.type.as_pointer())
                    builder.store(rhs, lhs2)

                elif mnemonic.text == "BRANCH":
                    value = pcode.find("input_0").text[2:-2]
                    if value in functions:
                        target = functions[value][0]
                        builder.call(target, [])
                    elif value in blocks:
                        target = blocks[value]
                        builder.branch(target)
                        no_branch = False
                    else:
                        # weird jump into some label in another function
                        # might be solved with callbr instruction?
                        builder.call(internal_functions["intra_function_branch"], [])

                elif mnemonic.text == "CBRANCH":
                    # This is a conditional branch instruction where the dynamic condition for taking the branch is
                    # determined by the 1 byte variable input1. If this variable is non-zero, the condition is
                    # considered true and the branch is taken. As in the BRANCH instruction the parameter input0 is
                    # not treated as a variable but as an address and is interpreted in the same way. Furthermore,
                    # a constant space address is also interpreted as a relative address so that a CBRANCH can do
                    # p-code relative branching. See the discussion for the BRANCH operation.

                    # P-CODE relative branching:
                    # If input0 is constant, i.e. its address space is the constant address space,
                    # then it encodes a p-code relative branch. In this case,
                    # the offset of input0 is considered a relative offset into the indexed
                    # list of p-code operations corresponding to the translation of the
                    # current machine instruction. This allows branching within the operations
                    # forming a single instruction. For example, if the BRANCH occurs as the
                    # pcode operation with index 5 for the instruction, it can branch to operation
                    # with index 8 by specifying a constant destination “address” of 3.
                    # Negative constants can be used for backward branches.
                    if relative_branch_index > 0:
                        print("Error relative cbranch not yet evaluated")
                    input = pcode.find("input_0").text
                    if pcode.find("input_0").get("storage") == "constant":
                        # new approach -> start counter with offset
                        current_index = int(pcode.tag.replace("pcode_", ""))
                        relative_offset = int(input, 16)
                        target_index = current_index + relative_offset
                        # Check if within valid range
                        pcodes = instruction.find("pcodes")
                        if 0 <= target_index < len(pcodes):
                            # true_target = pcodes[target_index]  # Retrieve the target pcode
                            relative_branch_index = relative_offset
                            # relative_branch['block_iterator'] = block_iterator
                            print(f"CBRANCH RELATIVE at address {address}")
                        else:
                            raise NotImplementedError("Negative relative p-code address not allowed.")
                        # continue
                        # # "0x3"
                        # print("p-code relative branching")
                        # # TODO - Implement p-code relative branching
                        # # get current p code index for instruction:
                        # current_index = int(pcode.tag.replace("pcode_", ""))
                        # # get offset value from constant
                        # # offset = int(input.replace("0x", ""))
                        # # Hexadecimal address offset
                        # offset = int(input, 16)
                        # print("offset: " + str(offset))
                        # # get jump pcode index:
                        # pcode_jump_index = current_index + offset
                        # # get branch address from p-code at offset index
                        # pcode_jump = instruction.find("pcodes")[pcode_jump_index]

                        # HOW TO GET P CODE SPECIFIC ADDRESS?
                        # builder.cmpxchg()
                        # LLLVM SIMILAR INSTRUCTION:
                        # https://en.cppreference.com/w/cpp/atomic/atomic/compare_exchange

                        # raise NotImplementedError("P-code relative branching has not been implemented!")
                    else:
                        if len(input) >= 5:#todo
                            true_target = blocks[input[2:-2]]
                        else:
                            print("Cbranch target address to short!")
                            true_target = blocks[input[2:]]
                    false_target = list(blocks.values())[block_iterator]
                    condition = fetch_input_varnode(builder, pcode.find("input_1"))
                    no_branch = False
                    # Ensure the condition is 1 bit wide
                    if isinstance(condition.type, ir.IntType) and condition.type.width == 8:  # truncate bools
                        condition = builder.trunc(condition, ir.IntType(1))

                    if relative_branch_index > 0:
                        relative_branch['false_target'] = false_target
                        relative_branch['condition'] = condition
                    else:
                        builder.cbranch(condition, true_target, false_target)

                elif mnemonic.text == "BRANCHIND":
                    no_branch = False
                    target = fetch_input_varnode(builder, pcode.find("input_0"))
                    if not target.type.is_pointer:
                        target = builder.inttoptr(target, target.type.as_pointer())
                    builder.branch_indirect(target)

                elif mnemonic.text == "CALL":
                    target = functions[pcode.find("input_0").text[2:-2]][0]
                    builder.call(target, [])

                elif mnemonic.text == "CALLIND":
                    # target = pcode.find("input_0").text[2:-2]
                    builder.call(internal_functions["call_indirect"], [])

                elif mnemonic.text == "USERDEFINED":
                    raise NotImplementedError("The USERDEFINED operation cannot be implemented")

                elif mnemonic.text == "RETURN":
                    input_1 = pcode.find("input_1")
                    no_branch = False
                    if input_1 is None:
                        builder.ret_void()
                    else:
                        raise NotImplementedError("RETURN operation that returns a value has not been implemented")

                elif mnemonic.text == "SUBPIECE":
                    output = pcode.find("output")
                    input_0 = pcode.find("input_0")
                    input_1 = pcode.find("input_1")
                    if input_1.text == "0x0":
                        val = fetch_input_varnode(builder, input_0)
                        result = builder.trunc(val, ir.IntType(int(output.get("size")) * 8))
                        update_output(builder, output, result)
                    else:
                        builder.call(internal_functions['bit_extraction'], [])

                elif mnemonic.text == "INT_EQUAL":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_unsigned('==', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_NOTEQUAL":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_unsigned('!=', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_LESS":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_unsigned('<', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_SLESS":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_signed('<', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_LESSEQUAL":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_unsigned('<=', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_SLESS_EQUAL":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.icmp_signed('<=', lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_ZEXT":
                    rhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    if rhs.type.is_pointer:
                        rhs = builder.ptrtoint(rhs, rhs.type.pointee)
                    if rhs.type.width < int(pcode.find("output").get("size")) * 8:
                        output = builder.zext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                    else:
                        output = builder.trunc(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_SEXT":
                    rhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    if rhs.type.is_pointer:
                        rhs = builder.ptrtoint(rhs, rhs.type.pointee)
                    output = builder.sext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_ADD":
                    input_0 = pcode.find("input_0")
                    input_1 = pcode.find("input_1")
                    lhs = fetch_input_varnode(builder, input_0)
                    rhs = fetch_input_varnode(builder, input_1)
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    if input_0.text in pointers and input_1.get("storage") == "constant":
                        result = builder.gep(lhs, [ir.Constant(int64, int(input_1.text, 16))])
                    else:
                        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                        result = builder.add(lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_SUB":
                    input_0 = pcode.find("input_0")
                    input_1 = pcode.find("input_1")
                    lhs = fetch_input_varnode(builder, input_0)
                    rhs = fetch_input_varnode(builder, input_1)
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)

                    if input_0.text in pointers and input_1.get("storage") == "constant":
                        result = builder.gep(lhs, [ir.Constant(int64, -int(input_1.text, 16))])
                    else:
                        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                        if rhs.type.width < lhs.type.width:
                            # Extend rhs to the size of lhs
                            rhs = builder.zext(rhs, lhs.type)
                        result = builder.sub(lhs, rhs)

                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_CARRY":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.uadd_with_overflow(lhs, rhs)
                    result = builder.extract_value(result, 1)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_SCARRY":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    result = builder.sadd_with_overflow(lhs, rhs)
                    result = builder.extract_value(result, 1)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_SBORROW":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
                    try:
                        result = builder.sadd_with_overflow(lhs, rhs)
                    except:
                        lhs, rhs = extend_operands(builder, lhs, rhs, pcode.find("input_0"), pcode.find("input_1"))
                        result = builder.sadd_with_overflow(lhs, rhs)

                    result = builder.extract_value(result, 1)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_2COMP":
                    val = fetch_input_varnode(builder, pcode.find("input_0"))
                    result = builder.not_(val)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_NEGATE":
                    val = fetch_input_varnode(builder, pcode.find("input_0"))
                    result = builder.neg(val)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "INT_XOR":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.xor(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_AND":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    try:
                        output = builder.and_(lhs, rhs)
                    except:
                        lhs, rhs = extend_operands(builder, lhs, rhs, pcode.find("input_0"), pcode.find("input_1"))
                        output = builder.and_(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_OR":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.or_(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_LEFT":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
                    output = builder.shl(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_RIGHT":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
                    output = builder.lshr(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_SRIGHT":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
                    output = builder.ashr(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_MULT":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.mul(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_DIV":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.div(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_REM":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.urem(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_SDIV":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.sdiv(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "INT_SREM":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    target = ir.IntType(int(pcode.find("output").get("size")) * 8)
                    lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
                    output = builder.srem(lhs, rhs)
                    update_output(builder, pcode.find("output"), output)

                elif mnemonic.text == "BOOL_NEGATE":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    result = builder.neg(lhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "BOOL_XOR":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    result = builder.xor(lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "BOOL_AND":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    result = builder.and_(lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "BOOL_OR":
                    lhs = fetch_input_varnode(builder, pcode.find("input_0"))
                    rhs = fetch_input_varnode(builder, pcode.find("input_1"))
                    result = builder.or_(lhs, rhs)
                    update_output(builder, pcode.find("output"), result)

                elif mnemonic.text == "POPCOUNT":
                    # <out> = POPCOUNT(<in>) roughly corresponds to LLVM's 'ctpop'
                    # followed by a zero extension to the output varnode's size.
                    inp_node = fetch_input_varnode(builder, pcode.find("input_0"))
                    out_node = pcode.find("output")
                    out_width = 8 * int(out_node.get("size"))

                    # NOTE: LLVM's 'ctpop' has a result with a size that is the same
                    # as the input. However, Ghidra's POPCOUNT might have a smaller
                    # or larger size. It is a little unclear how this really works.

                    result = builder.ctpop(inp_node)

                    if result.type.width < out_width:
                        result = builder.zext(result, ir.IntType(out_width))

                    elif result.type.width > out_width:
                        # This case is not defined clearly in the ghidra spec.
                        # However, truncating away the upper bytes should only be a
                        # problem if they are non-zero (i.e. there are more than 255
                        # 1-bits in the input varnode), which shouldn't happen.
                        # Still, let's add a check and a warning if it does happen.
                        # TODO: Create an issue to the Ghidra repo asking for clarification
                        # on what should happen in this case
                        if result.type.width > (1 << out_width):
                            print(
                                "[!] WARNING: POPCOUNT result might overflow the output node - LLVM IR might be inaccurate")

                        result = builder.trunc(result, ir.IntType(out_width))

                    update_output(builder, out_node, result)

                elif mnemonic.text == "LZCOUNT":
                    # Ghidra:
                    # <out> = LZCOUNT(<in>)
                    # This operator counts the number of zeros starting at the most
                    # significant bit. For instance, for a 4-byte varnode, a value
                    # of 0 returns 32, a value of 1 returns 31, and the value 2**31
                    # returns 0. The resulting count is zero extended into the
                    # output varnode.
                    src = fetch_input_varnode(builder, pcode.find("input_0"))
                    out_node = pcode.find("output")
                    out_width = 8 * int(out_node.get("size"))

                    # LLVM:
                    # ‘llvm.ctlz.*’
                    # declare i8 @llvm.ctlz.i8 (i8 <src>, i1 <is_zero_poison>)
                    # The ‘llvm.ctlz’ intrinsic counts the leading (most significant)
                    # zeros in a variable, or within each element of the vector. If
                    # src == 0 then the result is the size in bits of the type of
                    # src if is_zero_poison == 0 and poison otherwise.
                    FALSE = ir.Constant(ir.IntType(1), 0)
                    result = builder.ctlz(src, FALSE)

                    if out_width > src.type.width:
                        if result.type.width > out_width:
                            print("extend to smaller size value")
                        result = builder.zext(result, ir.IntType(out_width))
                    elif out_width < src.type.width:
                        result = builder.trunc(result, ir.IntType(out_width))

                    update_output(builder, out_node, result)
                elif mnemonic.text in {
                    "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
                    "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_NEG",
                    "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_CEIL", "FLOAT_FLOOR", "FLOAT_ROUND",
                    "FLOAT_NAN", "INT2FLOAT", "FLOAT2FLOAT", "TRUNC", "CPOOLREF",
                    "NEW", "MULTIEQUAL", "INDIRECT", "PTRADD", "PTRSUB", "CAST",
                    "PIECE",
                }:
                    raise NotImplementedError(f"PCODE opcode {mnemonic.text!r} is not implemented")

                else:
                    raise ValueError(f"{mnemonic.text!r} is not a standard pcode instruction")
            except NotImplementedError as e:
                print("ERROR: Not implemented instruction: " + mnemonic.text + " at: " + address)
            except ValueError as e:
                print("ValueError: Instruction: " + mnemonic.text + " at: " + address)
                print(str(pcode))
                print(str(e))
            except Exception as ex:
                raise ex
                errorType = str(type(ex)).replace("<class '", "").replace("'>", "")
                print(errorType + " at address: " + address)
                print(str(ex))

            # todo
            if close_branch:
                true_target = list(blocks.values())[block_iterator - 1].instructions[relative_branch['instruction_count']]
                builder.cbranch(relative_branch['condition'], true_target, relative_branch['false_target'])
                close_branch = False

        if block_iterator < len(blocks) and no_branch:
            builder.branch(list(blocks.values())[block_iterator])



def fetch_input_varnode(builder, name):
    var_type = name.get("storage")

    if var_type == "register":
        return builder.load(registers[name.text])

    elif var_type == "unique":
        try:
            return uniques[name.text]
        except KeyError:
            raise Exception("Temporary variable referenced before defined")

    elif var_type == "constant":
        var_size = int(name.get("size")) * 8
        return ir.Constant(ir.IntType(var_size), int(name.text, 0))

    elif var_type == "memory":
        return memory[name.text]

    raise ValueError(f"Unknown varnode storage {var_type} for {name}")


def update_output(builder, name, output):
    var_type = name.get("storage")
    if var_type == "register":
        try:
            reg = registers[name.text]
        except:
            print("could not find register to update output!")
            return
        
        if reg.type != output.type.as_pointer():
            reg = builder.bitcast(reg, output.type.as_pointer())
        builder.store(output, reg)
    elif var_type == "unique":
        # Make sure the output has the correct width - this fixes comparisons which
        # are 1 bit wide in LLVM, but 8 bits in PCODE
        out_size = int(name.get("size")) * 8
        out_type = output.type
        if isinstance(out_type, ir.IntType) and out_type.width < out_size:
            output = builder.zext(output, ir.IntType(out_size))

        uniques[name.text] = output


def fetch_output_varnode(name):
    var_type = name.get("storage")
    if var_type == "register":
        return registers[name.text]
    elif var_type == "unique":
        if name.text not in uniques:
            uniques[name.text] = None
        return uniques[name.text]


def int_check_inputs(builder, lhs, rhs, target):
    if lhs.type != target:
        if lhs.type.is_pointer:
            lhs2 = lhs
            lhs = builder.ptrtoint(lhs, target)
            if lhs2 == rhs:
                rhs = lhs
    if rhs.type != target and lhs != rhs:
        if rhs.type.is_pointer:
            rhs = builder.ptrtoint(rhs, target)
    return lhs, rhs


def extend_operands(builder, lhs, rhs, inputLhs, inputRhs):
    if inputLhs.get("storage") == "constant":
        if lhs.type.width < rhs.type.width:
            # Extend rhs to the size of lhs
            print("extending lhs - should this happen?")
            lhs = builder.zext(lhs, rhs.type)
    elif inputRhs.get("storage") == "constant":
        if rhs.type.width < lhs.type.width:
            # Extend rhs to the size of lhs
            rhs = builder.zext(rhs, lhs.type)
    return lhs, rhs

def check_shift_inputs(builder, lhs, rhs, target):
    if lhs.type != target:
        if lhs.type.is_pointer:
            lhs = builder.ptrtoint(lhs, target)
        else:
            lhs = builder.zext(lhs, target)
    if rhs.type != target:
        if rhs.type.is_pointer:
            rhs = builder.ptrtoint(rhs, target)
        else:
            if rhs.type.width > target.width:
                print("extend to smaller size value")
            rhs = builder.zext(rhs, target)

    return lhs, rhs


def int_comparison_check_inputs(builder, lhs, rhs):
    # For integer comparison operations, we make sure both operands are integers
    # (and not pointers).
    left_is_ptr = lhs.type.is_pointer
    right_is_ptr = rhs.type.is_pointer

    if not left_is_ptr and not right_is_ptr:
        pass
    elif left_is_ptr and not right_is_ptr:
        lhs = builder.ptrtoint(lhs, rhs.type)
    elif not left_is_ptr and right_is_ptr:
        rhs = builder.ptrtoint(rhs, lhs.type)
    else:
        raise ValueError(f"Both sides of integer comparison are pointers! ({lhs.type=} and {rhs.type=})")

    return lhs, rhs
