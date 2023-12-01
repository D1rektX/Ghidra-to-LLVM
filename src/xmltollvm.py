from llvmlite import ir
import xml.etree.ElementTree as et

int32 = ir.IntType(32)
int64 = ir.IntType(64)
int1 = ir.IntType(1)
void_type = ir.VoidType()
function_names = []
registers, functions, uniques, extracts = {}, {}, {}, {}
internal_functions = {}
memory = {}
flags = ["ZF", "CF", "OF", "SF"]
pointers = ["RSP", "RIP", "RBP", "EBP", "ESP"]


def lift(filename):
    root = et.parse(filename).getroot()
    module = ir.Module(name="lifted")

    # track unimplemented methods
    not_implemented_pcodes = []

    for register in root.find('globals').findall('register'):
        if register.get('name') in flags:
            var = ir.GlobalVariable(module, ir.IntType(1), register.get('name'))
            var.initializer = ir.Constant(ir.IntType(1), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var
        elif register.get('name') in pointers:
            var = ir.GlobalVariable(module, ir.PointerType(ir.IntType(8)), register.get('name'))
            var.initializer = ir.Constant(ir.PointerType(ir.IntType(8)), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var
        else:
            var = ir.GlobalVariable(module, ir.IntType(8 * int(register.get('size'))), register.get('name'))
            var.initializer = ir.Constant(ir.IntType(8 * int(register.get('size'))), None)
            var.linkage = 'internal'
            registers[register.get('name')] = var

    for memory_location in root.find('memory').findall('memory'):
        var = ir.GlobalVariable(module, ir.IntType(8 * int(memory_location.get('size'))), memory_location.get('name'))
        var.initializer = ir.Constant(ir.IntType(8 * int(memory_location.get('size'))), None)
        var.linkage = 'internal'
        memory[memory_location.get('name')] = var

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "intra_function_branch")
    internal_functions["intra_function_branch"] = ir_func

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "call_indirect")
    internal_functions["call_indirect"] = ir_func

    func_return = ir.VoidType()
    fnty = ir.FunctionType(func_return, [])
    ir_func = ir.Function(module, fnty, "bit_extraction")
    internal_functions["bit_extraction"] = ir_func

    for function in root.findall('function'):
        name = function.get('name')
        x = 1
        while name in function_names:
            name = name + "_" + str(x)
            x += 1
        function_names.append(name)
        address = function.get('address')
        functions[address] = [build_function(name, module), function]

    for address in functions:
        ir_func, function = functions[address]
        populate_func(ir_func, function, not_implemented_pcodes)

    return module


def populate_func(ir_func, function, not_implemented_pcodes):
    builders, blocks = build_cfg(function, ir_func)
    if blocks == {}:
        return
    populate_cfg(function, builders, blocks, not_implemented_pcodes)


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


# noinspection DuplicatedCode
def populate_cfg(function, builders, blocks, not_implemented_pcodes):
    builder = builders["entry"]
    stack_size = 10 * 1024 * 1024
    stack = builder.alloca(ir.IntType(8), stack_size, name="stack")
    stack_top = builder.gep(stack, [ir.Constant(int64, stack_size - 8)], name="stack_top")
    builder.store(stack_top, registers["RSP"])
    builder.branch(list(blocks.values())[1])
    block_iterator = 1
    instr = 0
    quiter = False
    for instruction in function.find("instructions"):
        if quiter:
            break
        address = instruction.find("address").text
        if address in builders:
            builder = builders[address]
        pcodes = instruction.find("pcodes")
        pc = 0
        no_branch = True
        for pcode in pcodes:
            pc += 1
            mnemonic = pcode.find("name")
            try:
                parsePCodeInstruction(builder, mnemonic.text, pcode)
            except Exception as ex:
                if "Not implemented" not in str(ex):
                    print(str(ex))
                opcode = str(mnemonic.text)
                if not opcode in not_implemented_pcodes:
                    not_implemented_pcodes.append(opcode)
                    print("Error parsing P-code " + str(mnemonic.text))
        block_iterator += 1
        instr += 1
        if block_iterator < len(blocks) and no_branch:
            try:
                builder.branch(list(blocks.values())[block_iterator])
            except Exception as ex:
                print(f"Error: {str(ex)}" )



def parsePCodeInstruction(builder, mnemonic, pcode):
    if mnemonic == "COPY":
        output = pcode.find("output")
        if output.text in flags and pcode.find("input_0").get("storage") == "constant":
            source = ir.Constant(ir.IntType(1), int(pcode.find("input_0").text, 0))
        else:
            source = fetch_input_varnode(builder, pcode.find("input_0"))
        update_output(builder, pcode.find("output"), source)
    elif mnemonic == "LOAD":
        input_1 = pcode.find("input_1")
        output = pcode.find("output")
        rhs = fetch_input_varnode(builder, input_1)
        if input_1.get("storage") == "unique" and output.get("storage") == "unique":
            # This is incorrect. This is treating it as a copy, should load the memory address in the input 1
            update_output(builder, output, rhs)
        else:
            if input_1.text in pointers:
                rhs = builder.gep(rhs, [ir.Constant(int64, 0)])
            result = builder.load(rhs)
            update_output(builder, output, result)
    elif mnemonic == "STORE":
        input_1 = pcode.find("input_1")  # target
        input_2 = pcode.find("input_2")  # source
        rhs = fetch_input_varnode(builder, input_2)
        lhs = fetch_output_varnode(input_1)
        lhs2 = builder.gep(lhs, [ir.Constant(int64, 0)])
        if lhs2.type != rhs.type.as_pointer():
            lhs2 = builder.bitcast(lhs2, rhs.type.as_pointer())
        builder.store(rhs, lhs2)
    elif mnemonic == "BRANCH":
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
    elif mnemonic == "CBRANCH":
        true_target = blocks[pcode.find("input_0").text[2:-2]]
        false_target = list(blocks.values())[block_iterator + 1]
        condition = fetch_input_varnode(builder, pcode.find("input_1"))
        no_branch = False
        builder.cbranch(condition, true_target, false_target)
    elif mnemonic == "BRANCHIND":
        no_branch = False
        target = fetch_input_varnode(builder, pcode.find("input_0"))
        if not target.type.is_pointer:
            target = builder.inttoptr(target, target.type.as_pointer())
        builder.branch_indirect(target)
    elif mnemonic == "CALL":
        target = functions[pcode.find("input_0").text[2:-2]][0]
        builder.call(target, [])
    elif mnemonic == "CALLIND":
        # target = pcode.find("input_0").text[2:-2]
        builder.call(internal_functions["call_indirect"], [])
    elif mnemonic == "USERDEFINED":
        raise Exception("Not implemented")
    elif mnemonic == "RETURN":
        input_1 = pcode.find("input_1")
        no_branch = False
        if input_1 is None:
            builder.ret_void()
        else:
            raise Exception("Return value being passed")
    elif mnemonic == "PIECE":
        raise Exception("PIECE operation needs to be tested")
    elif mnemonic == "SUBPIECE":
        output = pcode.find("output")
        input_0 = pcode.find("input_0")
        input_1 = pcode.find("input_1")
        if input_1.text == "0x0":
            val = fetch_input_varnode(builder, input_0)
            result = builder.trunc(val, ir.IntType(int(output.get("size")) * 8))
            update_output(builder, output, result)
        else:
            builder.call(internal_functions['bit_extraction'], [])
    elif mnemonic == "INT_EQUAL":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_unsigned('==', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_NOTEQUAL":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_unsigned('!=', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_LESS":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_unsigned('<', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_SLESS":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_signed('<', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_LESSEQUAL":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_unsigned('<=', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_SLESS_EQUAL":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.icmp_signed('<=', lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_ZEXT":
        rhs = fetch_input_varnode(builder, pcode.find("input_0"))
        if rhs.type.is_pointer:
            rhs = builder.ptrtoint(rhs, rhs.type.pointee)
        output = builder.zext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_SEXT":
        rhs = fetch_input_varnode(builder, pcode.find("input_0"))
        if rhs.type.is_pointer:
            rhs = builder.ptrtoint(rhs, rhs.type.pointee)
        output = builder.sext(rhs, ir.IntType(int(pcode.find("output").get("size")) * 8))
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_ADD":
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
    elif mnemonic == "INT_SUB":
        input_0 = pcode.find("input_0")
        input_1 = pcode.find("input_1")
        lhs = fetch_input_varnode(builder, input_0)
        rhs = fetch_input_varnode(builder, input_1)
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        if input_0.text in pointers and input_1.get("storage") == "constant":
            result = builder.gep(lhs, [ir.Constant(int64, -int(input_1.text, 16))])
        else:
            lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
            result = builder.sub(lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_CARRY":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.uadd_with_overflow(lhs, rhs)
        result = builder.extract_value(result, 1)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_SCARRY":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.sadd_with_overflow(lhs, rhs)
        result = builder.extract_value(result, 1)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_SBORROW":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        lhs, rhs = int_comparison_check_inputs(builder, lhs, rhs)
        result = builder.sadd_with_overflow(lhs, rhs)
        result = builder.extract_value(result, 1)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_2COMP":
        val = fetch_input_varnode(builder, pcode.find("input_0"))
        result = builder.not_(val)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_NEGATE":
        val = fetch_input_varnode(builder, pcode.find("input_0"))
        result = builder.neg(val)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "INT_XOR":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.xor(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_AND":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.and_(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_OR":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.or_(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_LEFT":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
        output = builder.shl(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_RIGHT":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
        output = builder.lshr(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_SRIGHT":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = check_shift_inputs(builder, lhs, rhs, target)
        output = builder.ashr(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_MULT":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.mul(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_DIV":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.div(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_REM":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.urem(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_SDIV":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.sdiv(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "INT_SREM":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        target = ir.IntType(int(pcode.find("output").get("size")) * 8)
        lhs, rhs = int_check_inputs(builder, lhs, rhs, target)
        output = builder.srem(lhs, rhs)
        update_output(builder, pcode.find("output"), output)
    elif mnemonic == "BOOL_NEGATE":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        result = builder.neg(lhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "BOOL_XOR":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        result = builder.xor(lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "BOOL_AND":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        result = builder.and_(lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "BOOL_OR":
        lhs = fetch_input_varnode(builder, pcode.find("input_0"))
        rhs = fetch_input_varnode(builder, pcode.find("input_1"))
        result = builder.or_(lhs, rhs)
        update_output(builder, pcode.find("output"), result)
    elif mnemonic == "POPCOUNT":
        raise Exception("Not implemented")
        input_var = fetch_input_varnode(builder, pcode.find("input_0"))
        result = popcount(builder, input_var)
        update_output(builder, pcode.find("output"), result)
        # raise Exception("Not implemented")
    elif mnemonic == "FLOAT_EQUAL":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_NOTEQUAL":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_LESS":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_LESSEQUAL":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_ADD":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_SUB":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_MULT":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_DIV":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_NEG":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_ABS":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_SQRT":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_CEIL":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_FLOOR":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_ROUND":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT_NAN":
        raise Exception("Not implemented")
    elif mnemonic == "INT2FLOAT":
        raise Exception("Not implemented")
    elif mnemonic == "FLOAT2FLOAT":
        raise Exception("Not implemented")
    elif mnemonic == "TRUNC":
        raise Exception("Not implemented")
    elif mnemonic == "CPOOLREF":
        raise Exception("Not implemented")
    elif mnemonic == "NEW":
        raise Exception("Not implemented")
    elif mnemonic == "MULTIEQUAL":
        raise Exception("Not implemented")
    elif mnemonic == "INDIRECT":
        raise Exception("Not implemented")
    elif mnemonic == "PTRADD":
        raise Exception("Not implemented")
    elif mnemonic == "PTRSUB":
        raise Exception("Not implemented")
    elif mnemonic == "CAST":
        raise Exception("Not implemented")
    else:
        raise Exception("Not a standard pcode instruction")


def popcount(builder, value):
    # input = fetch_input_varnode(builder, pcode.find("input_0"))
    # input = builder.trunc(input, ir.IntType(8))
    # count = builder.trunc(input, ir.IntType(8))  # Truncate the input to the desired bit width
    # result = builder.mul(count, ir.Constant(ir.IntType(8), 0))
    #
    # while input.type.width > 0:
    #     count = builder.sub(count, ir.Constant(ir.IntType(8), 1))
    #     result = builder.add(result, builder.and_(input, count))
    #
    # update_output(builder, pcode.find("output"), result)

    # Implementing POPCOUNT logic using LLVM IR
    # Assuming 32-bit integers for illustration
    i = 0
    count = builder.trunc(value, ir.IntType(32))
    res = builder.mul(count, ir.Constant(ir.IntType(32), 0))

    while count.type.width > 0:
        i = i + 1
        if i % 1000 == 0:
            print(i)
        count = builder.sub(count, ir.Constant(count.type, 1))
        res = builder.add(res, builder.and_(value, count))

    return res

def fetch_input_varnode(builder, name):
    var_type = name.get("storage")
    var_size = int(name.get("size")) * 8
    if var_type == "register":
        return builder.load(registers[name.text])
    elif var_type == "unique":
        if name.text not in list(uniques.keys()):
            raise Exception("Temporary variable referenced before defined")
        return uniques[name.text]
    elif var_type == "constant":
        var = ir.Constant(ir.IntType(var_size), int(name.text, 0))
        return var
    elif var_type == "memory":
        return memory[name.text]


def update_output(builder, name, output):
    var_type = name.get("storage")
    if var_type == "register":
        reg = registers[name.text]
        if reg.type != output.type.as_pointer():
            reg = builder.bitcast(reg, output.type.as_pointer())
        builder.store(output, reg)
    elif var_type == "unique":
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
            rhs = builder.zext(rhs, target)

    return lhs, rhs


def int_comparison_check_inputs(builder, lhs, rhs):
    # For integer comparison operations. We assume rhs is the correct type.
    if lhs.type.is_pointer:
        lhs = builder.ptrtoint(lhs, rhs.type)
    return lhs, rhs