from cpu import CpuContext
from flags import FlagsContext
from my_globals import idc, ida_auto, ida_bytes, ida_ua, ida_xref, ida_allins, idautils, ctypes, idaapi, __JUMP_LIMIT__, __OPER_COUNT__, __ARITHMETIC__, __COMPARATIVE__, SkippedDataState
from debug_messages import exec_flow_shift_msg,unhandled_jump_msg
#main
def deobfuscate_false_uncond_jumps_and_calls(effective_address: idaapi.ea_t = idc.here(),
                                             context          : CpuContext  = CpuContext(), 
                                             jump_count       : int         = 0)->int:
    
    frame_start: idaapi.ea_t = effective_address
    while True:
        instruction: ida_ua.insn_t = idautils.DecodeInstruction(effective_address)
        context.registers[idautils.procregs.eip.reg].value = effective_address
        if not ida_bytes.is_code(ida_bytes.get_flags(effective_address)) or jump_count >= __JUMP_LIMIT__:
            if jump_count >= __JUMP_LIMIT__:
                print(f'[✓] Taken {__JUMP_LIMIT__} jumps, all finished.')
                break
            print(f'[✕] Not code @{effective_address:x}, breaking the loop.')
            break

        if instruction.itype == ida_allins.NN_call:
            print(f'[i] Called @{instruction.Op1.addr:x} from {instruction.ea:x}')
            if not handle_forward_movement(instruction):
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
            effective_address = instruction.Op1.addr
            frame_start = instruction.Op1.addr
            jump_count += 1
            continue

        if is_non_cond_jump(instruction):
            exec_flow_shift_msg(instruction)
            effective_address = instruction.Op1.addr
            frame_start = instruction.Op1.addr
            jump_count += 1
            continue

        if is_cond_jump(instruction):
            if context.eval_cond_jump(instruction.itype):
                if is_junk_condition(instruction, frame_start): print(f'[✓] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found to be junk!')
                else: print(f'[i] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found NOT to be junk!'); break
                if not handle_forward_movement(instruction):
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
                effective_address = instruction.Op1.addr
                frame_start = instruction.Op1.addr
                jump_count += 1
                continue

        if is_arithmetic(instruction) and instruction.Op2.type == ida_ua.o_imm:
            context.update(instruction)

        effective_address += instruction.size

    return 0

def handle_forward_movement(instruction: ida_ua.insn_t)->bool:
    if not are_skipped_instructions_junk(instruction):
        print(f'[i] Data skipped from @{instruction.ea:x} to @{instruction.Op1.addr:x} has been found to be NOT junk!')
        return True
    
    print(f'[✓] Data skipped from @{instruction.ea:x} to @{instruction.Op1.addr:x} has been found to be junk!')
    
    if ida_bytes.del_items(instruction.ea + instruction.size, ida_bytes.DELIT_SIMPLE, instruction.Op1.addr - instruction.size - instruction.ea):
        print(f'[✓] Undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
        if not ida_bytes.is_code(ida_bytes.get_flags(instruction.Op1.addr)):
            print( f'[i] Byte @{instruction.Op1.addr:x} has been found to be undefined, attempting to create a new instruction...')
            new_len: int = ida_ua.create_insn(instruction.Op1.addr)
            
            if new_len:
                print(f'[✓] Created a new instruction @{instruction.Op1.addr:x}')
                return True
            else: 
                print(f'[✕] Failed to undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
        else: 
            print(f'[✓] @{instruction.Op1.addr} has been found to be a Head of type Code!')
    else: 
        print(f'[✕] Failed to undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
    
    return False

def contains_imm( operand_types: list[int])->bool: return ida_ua.o_imm  in operand_types
def contains_near(operand_types: list[int])->bool: return idaapi.o_near in operand_types
def contains_reg( operand_types: list[int])->bool: return ida_ua.o_reg  in operand_types

def get_operands_types(operand_objects: list[ida_ua.op_t] | None = None, instruction: ida_ua.insn_t | None = None)->list[int]:
    try:
        if not operand_objects:
            if not isinstance(instruction, ida_ua.insn_t):
                raise TypeError
            operand_objects = get_operand_objects(instruction)
        return [operand.type for operand in operand_objects]
    except TypeError:
        print("[x] get_operand_types::Error { No input was passed! }")
        return []

def get_operand_objects(instruction: ida_ua.insn_t)->list[ida_ua.op_t]:
    result: list[ida_ua.op_t] = []
    for i in range(__OPER_COUNT__):
        if instruction[i].type == idaapi.o_void:
            break
        result.append(instruction[i])
    return result

def is_arithmetic(      instruction: ida_ua.insn_t)->bool: return instruction.itype in __ARITHMETIC__
def is_cond_jump(       instruction: ida_ua.insn_t)->bool: return ida_allins.NN_ja  <= instruction.itype <= ida_allins.NN_jz
def is_non_cond_jump(   instruction: ida_ua.insn_t)->bool: return ida_allins.NN_jmp <= instruction.itype <= ida_allins.NN_jmpshort

def is_junk_condition(  instruction: ida_ua.insn_t, eval_start: idaapi.ea_t)->bool:
    last_executed_instruction: ida_ua.insn_t = instruction
    current_eval_instruction : ida_ua.insn_t = idautils.DecodeInstruction(eval_start)
    case_operand             : ida_ua.op_t   = last_executed_instruction.Op1
    if ( case_operand.type == ida_ua.o_reg and last_executed_instruction.itype in __ARITHMETIC__
        or last_executed_instruction.itype in  __COMPARATIVE__ and last_executed_instruction.Op2.type  != idaapi.o_phrase):
        while current_eval_instruction.ea  <=  instruction.ea:
            if (current_eval_instruction.Op2.type == idaapi.o_imm
            and current_eval_instruction.Op1.reg  == case_operand.reg
            and current_eval_instruction.itype    == ida_allins.NN_mov):
                return True
            current_eval_instruction = idautils.DecodeInstruction(current_eval_instruction.ea + current_eval_instruction.size)
    return False

def are_skipped_instructions_junk(instruction: ida_ua.insn_t)->bool:
    addresses_delta: int = helper_delta(instruction)
    if not addresses_delta:
        return False
    eval_instruction: ida_ua.insn_t = instruction
    next_addr       : idaapi.ea_t   = instruction.ea + instruction.size
    while next_addr <= instruction.Op1.addr:
        second_referer: idaapi.ea_t = ida_xref.get_next_cref_to(eval_instruction.ea, ida_xref.get_first_cref_to(eval_instruction.ea))
        if second_referer != idc.BADADDR and second_referer != idc.BADADDR != instruction.ea: return False
        elif not ida_bytes.is_code(ida_bytes.get_flags(next_addr)):
            match are_skipped_unexplored_bytes_junk(next_addr, instruction.Op1.addr):
                case SkippedDataState.FINISHED_IS_NOT_JUNK        : return False
                case SkippedDataState.FINISHED_IS_JUNK            : return True
                case SkippedDataState.NOT_FINISHED_IS_CODE        : continue
        eval_instruction = idautils.DecodeInstruction(next_addr)
        next_addr        = eval_instruction.ea + eval_instruction.size
    return True

def helper_delta(instruction: ida_ua.insn_t)->int:
    addresses_delta: idaapi.ea_t = instruction.size -instruction.ea
    if 0 > addresses_delta: 
        print(f'[i] Addresses Delta @{instruction.ea:x} has been found to be negative!')
    elif addresses_delta > 0x800: 
        print(f'[i] Addresses Delta @{instruction.ea:x} is shifting forward the execution flow more than 2048 bytes, this is not a junk execution flow shift!')
    return addresses_delta

def are_skipped_unexplored_bytes_junk(effective_address: idaapi.ea_t, destination_address: idaapi.ea_t)->SkippedDataState:
    current_address: idaapi.ea_t = effective_address
    while current_address <= destination_address:
        first_xref: int    = ida_xref.get_first_cref_to(effective_address)
        print(f'[i] Skipped byte @{effective_address:x} is not referenced by future code')
        effective_address += 1
        if not first_xref:
            print(f'[i] Skipped byte @{effective_address:x} is not referenced by ANY code')
            continue
        if ida_xref.get_next_cref_to(effective_address, first_xref) != idc.BADADDR:
            return SkippedDataState.FINISHED_IS_NOT_JUNK
        elif ida_bytes.is_code(ida_bytes.get_flags(effective_address)): return SkippedDataState.NOT_FINISHED_IS_CODE
    return SkippedDataState.FINISHED_IS_JUNK

if __name__ == '__main__':
    idaapi.msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(deobfuscate_false_uncond_jumps_and_calls())}')