from cpu import CpuContext
from memory import StackFrame
from my_globals import __JUMP_LIMIT__,  __ARITHMETIC__, __COMPARATIVE__, __STACK_OPS__, __BITWISE_OPS__
import idc, ida_auto, ida_bytes, ida_ua, ida_allins, idautils,idaapi
from instruction_helper import InstructionHelper
from idautils import DecodeInstruction, procregs
from idaapi import ea_t, msg_clear

def main(effective_address: ea_t       = idc.here(),
         context          : CpuContext        = CpuContext(),
         jump_count       : int               = 0,
         helper           : InstructionHelper = InstructionHelper())->int:
    stack      : StackFrame    = StackFrame(effective_address, context.reg_bp, context.reg_sp)
    eval_start : ea_t          = effective_address
    instruction: ida_ua.insn_t
    while True:
        print(f'{effective_address:x}')
        context.registers[procregs.eip.reg].value = effective_address
        instruction = DecodeInstruction(effective_address)
        if jump_count >= __JUMP_LIMIT__:
            break

        if not instruction:
            print(f'[✕] Not code @{effective_address:x}, breaking the loop.')
            break

        elif instruction.itype in [ida_allins.NN_retn, ida_allins.NN_retf]:
            idc.jumpto(effective_address)
            break

        helper.set_instruction(instruction)

        if helper.is_stack_op():
            oper_value = helper.get_oper_value(0, context, stack)
            stack.handle_stack_operation(instruction, oper_value)
            print(stack)

        elif helper.is_comparative():
            if  not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif helper.is_bitwise_op():
            if  not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif helper.is_cond_jump():
            print("[i] Evaluating a conditional jump")
            if context.eval_cond_jump(instruction.itype):

                if helper.is_junk_condition(eval_start):
                    print(f'[✓] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found to be junk!')
                else:
                    print(f'[i] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found NOT to be junk!')
                if not helper.handle_forward_movement():
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
                effective_address = instruction.Op1.addr
                eval_start        = effective_address
                jump_count       += 1
            else:
                effective_address += instruction.size
            continue

        elif helper.is_cond_mov():
            if context.eval_cond_mov(instruction.itype):
                instruction.itype = ida_allins.NN_mov
                context.update_regs_n_flags(instruction)

        elif helper.is_non_cond_jump():
            exec_flow_shift_msg(instruction)
            effective_address = instruction.Op1.addr
            eval_start        = effective_address
            jump_count       += 1
            effective_address = instruction.Op1.addr

            continue

        elif helper.is_call_inst():
            print(f'[i] Called @{instruction.Op1.addr:x} from {instruction.ea:x}')
            if not helper.are_skipped_instructions_junk():
                stack = stack.create_called_frame(instruction.Op1.addr, context.reg_bp, context.reg_sp)

            if not helper.handle_forward_movement():
                print('[✕] Handle Forward Movement Failed! breaking the loop')
                break

            effective_address = instruction.Op1.addr
            eval_start        = effective_address
            jump_count       += 1
            continue

        elif helper.is_arithmetic():
            if helper.validate_stack_regs_op():
                if instruction.Op2.type == ida_ua.o_reg :
                    stack.handle_stack_operation(instruction, context.registers[instruction.Op2.reg].value)

                elif instruction.Op2.type == ida_ua.o_imm:
                    stack.handle_stack_operation(instruction, instruction.Op2.value)
                    print(stack)

            if not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif helper.is_non_cond_mov():
            if not helper.validate_stack_regs_op():
                if instruction.Op1.type == ida_ua.o_reg:
                    context.update_regs_n_flags(instruction)
            else:
                helper.validate_operands()
                stack.handle_stack_operation(instruction, helper.get_oper_value(1, context, stack), helper.retrieve_stack_addr(context))

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
    msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(main())}')
