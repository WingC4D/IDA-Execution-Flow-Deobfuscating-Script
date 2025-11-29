from cpu import CpuContext
from memory import StackFrame
from my_globals import __JUMP_LIMIT__,  __ARITHMETIC__, __COMPARATIVE__, __STACK_OPS__, __BITWISE_OPS__
import idc, ida_auto, ida_bytes, ida_ua, ida_allins, idautils,idaapi
from instruction_helper import InstructionHelper

def main(effective_address: idaapi.ea_t       = idc.here(),
         context          : CpuContext        = CpuContext(),
         jump_count       : int               = 0,
         helper           : InstructionHelper = InstructionHelper())->int:
    stack       : StackFrame        = StackFrame(effective_address)
    eval_start  : idaapi.ea_t       = effective_address

    instruction : ida_ua.insn_t
    while True:
        context.registers[idautils.procregs.eip.reg].value = effective_address

        if jump_count >= __JUMP_LIMIT__:
            break
        instruction = idautils.DecodeInstruction(effective_address)
        if not instruction:
            print(f'[✕] Not code @{effective_address:x}, breaking the loop.')
            break
        helper.set_instruction(instruction)

        if instruction.itype in [ida_allins.NN_retn, ida_allins.NN_retf]:
            idc.jumpto(effective_address)
            break

        elif instruction.itype in __ARITHMETIC__:
            if instruction.Op1.type == instruction.Op2.type:
                if instruction.Op1.type == ida_ua.o_reg:
                    if instruction.Op1.reg == idautils.procregs.ebp.reg:
                        if instruction.Op2.reg == idautils.procregs.esp.reg:
                            stack.handle_stack_operation(instruction, context.reg_sp)
                            stack.create_called_frame(eval_start)
                            print(stack)
            if  not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif instruction.itype in __STACK_OPS__:
            if instruction.Op1.type == ida_ua.o_imm:
                right_oper_value: int = instruction.Op1.value

            elif instruction.Op1.type == ida_ua.o_reg:
                right_oper_value: int = context.registers[instruction.Op1.reg].value

            elif instruction.Op1.type == ida_ua.o_displ:

                if instruction.Op1.phrase == idautils.procregs.ebp.reg:
                    right_oper_value = stack.data[instruction.Op1.addr].data

                elif instruction.Op1.phrase == idautils.procregs.esp.reg:
                    right_oper_value = stack.data[stack.top + instruction.Op1.addr].data

                else:
                    break
            else:
                idc.jumpto(effective_address)
                break
            stack.handle_stack_operation(instruction, right_oper_value)
            print(stack)

        elif instruction.itype in __COMPARATIVE__:
            if  not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif instruction.itype in __BITWISE_OPS__:
            if  not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif helper.is_cond_jump():
            if context.eval_cond_jump(instruction.itype):
                if helper.is_junk_condition(eval_start):
                    print(f'[✓] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found to be junk!')
                else:
                    print(f'[i] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found NOT to be junk!')
                if not helper.handle_forward_movement():
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
                jump_count       += 1
                effective_address = instruction.Op1.addr
            continue

        elif helper.is_non_cond_jump():
            exec_flow_shift_msg(instruction)
            effective_address = instruction.Op1.addr
            eval_start        = effective_address
            jump_count       += 1
            effective_address = instruction.Op1.addr

            continue

        elif ida_allins.NN_call <= instruction.itype <= ida_allins.NN_callni:
            print(f'[i] Called @{instruction.Op1.addr:x} from {instruction.ea:x}')

            if not helper.handle_forward_movement():
                print('[✕] Handle Forward Movement Failed! breaking the loop')
                break

            effective_address = instruction.Op1.addr
            eval_start        = effective_address
            jump_count       += 1
            continue

        else:
            idc.jumpto(effective_address)
            print(f"[?] But, What Is That?! @{effective_address:x}")
            break

        effective_address += instruction.size
    print(context, stack)
    idc.jumpto(effective_address)
    return 0

def exec_flow_shift_msg(instruction: ida_ua.insn_t)->None:
    return print(f'jumped to @{instruction.Op1.addr:x} from @{instruction.ea:x}')

if __name__ == '__main__':
    idaapi.msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(main())}')
