from managers   import EmulationManager, __INT__
from my_globals import __JUMP_LIMIT__
from idautils   import DecodeInstruction, procregs
from idaapi     import ea_t, msg_clear
from idc import jumpto, here
import ida_auto, ida_ua, ida_allins

def main(e_manager: EmulationManager = EmulationManager(here()), jump_count:int = 0)->int:
    eval_start: ea_t = e_manager.ea
    instruction: ida_ua.insn_t
    while True:
        print(f'{e_manager.ea:x}')
        e_manager.cpu.gen_registers[procregs.eip.reg].value = e_manager.ea
        instruction                                        = DecodeInstruction(e_manager.ea)
        if jump_count >= __JUMP_LIMIT__: break

        if not instruction:
            print(f'[✕] Not code @{e_manager.ea:x}, breaking the loop.')
            break

        elif instruction.itype in [ida_allins.NN_retn, ida_allins.NN_retf]:
            jumpto(e_manager.ea)
            break

        e_manager.helper.set_instruction(instruction)

        if e_manager.helper.is_stack_op():
            res = e_manager.handle_operation_stack(e_manager.extract_oper_value(0), e_manager.stack.top)
            if instruction.itype == ida_allins.NN_pop:
                e_manager.cpu.gen_registers[instruction.Op1.reg].value = res
            print(e_manager.cpu)

        elif e_manager.helper.is_comparative():
            if not e_manager.cpu.update_regs_n_flags(instruction, e_manager.extract_oper_value(-1)):
                jumpto(e_manager.ea)
                break

        elif e_manager.helper.is_bitwise_op():
            if not e_manager.cpu.update_regs_n_flags(instruction, e_manager.extract_oper_value(-1)):
                jumpto(e_manager.ea)
                break

        elif e_manager.helper.is_cond_jump():
            print("[i] Evaluating a conditional jump")
            if e_manager.cpu.eval_cond_jump(instruction.itype):

                if e_manager.helper.is_junk_condition(eval_start):
                    print(f'[✓] Conditional jump @{e_manager.ea:x} of type: {hex(instruction.itype)} has been found to be junk!')
                else:
                    print(f'[i] Conditional jump @{e_manager.ea:x} of type: {hex(instruction.itype)} has been found NOT to be junk!')
                if not e_manager.helper.handle_forward_movement():
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
                e_manager.ea = instruction.Op1.addr
                eval_start        = e_manager.ea
                jump_count       += 1
            else:
                e_manager.ea += instruction.size
            continue

        elif e_manager.helper.is_cond_mov():
            if e_manager.cpu.eval_cond_mov(instruction.itype):
                instruction.itype = ida_allins.NN_mov
                e_manager.cpu.update_regs_n_flags(instruction,  e_manager.extract_oper_value(-1))

        elif e_manager.helper.is_non_cond_jump():
            exec_flow_shift_msg(instruction)
            if not e_manager.helper.handle_forward_movement():
                exit(-4)
            e_manager.ea = instruction.Op1.addr
            eval_start        = e_manager.ea
            jump_count       += 1
            e_manager.ea = instruction.Op1.addr

            continue

        elif e_manager.helper.is_call_inst():
            print(f'[i] Called @{instruction.Op1.addr:x} from {instruction.ea:x}')
            if not e_manager.helper.are_skipped_instructions_junk():
                e_manager.stack = e_manager.stack.create_called_frame(instruction.Op1.addr, e_manager.cpu.reg_bp, e_manager.cpu.reg_sp)

            if not e_manager.helper.handle_forward_movement():
                print('[✕] Handle Forward Movement Failed! breaking the loop')
                break

            e_manager.ea = instruction.Op1.addr
            eval_start        = e_manager.ea
            jump_count       += 1
            continue

        elif e_manager.helper.is_arithmetic_add():
            op_value = e_manager.extract_oper_value(1)
            if e_manager.helper.validate_stack_ref():
                reg_const: int = -1
                match instruction.Op1.type:
                    case ida_ua.o_reg:
                        reg_const = instruction.Op1.reg

                    case ida_ua.o_displ | ida_ua.o_phrase:
                        reg_const  = instruction.Op1.phrase

                    case default:
                        jumpto(e_manager.ea)
                        break
                new_index = e_manager.cpu.gen_registers[reg_const].value + __INT__(instruction.Op1.addr).value
                e_manager.handle_operation_stack(op_value, new_index)

            if not e_manager.cpu.update_regs_n_flags(instruction, op_value):
                jumpto(e_manager.ea)
                break

        elif e_manager.helper.is_arithmetic_mul():
            oper_value = e_manager.extract_oper_value(-1)
            e_manager.cpu.update_regs_n_flags(instruction, oper_value)

        elif e_manager.helper.is_non_cond_mov():
            oper_value =  e_manager.extract_oper_value(-1)
            if not e_manager.helper.validate_stack_ref():
                if instruction.Op1.type == ida_ua.o_reg:
                    e_manager.cpu.update_regs_n_flags(instruction, oper_value)

            else:
                e_manager.handle_operation_stack(e_manager.extract_oper_value(1), e_manager.helper.retrieve_stack_addr(e_manager.cpu, 0))

        else:
            jumpto(e_manager.ea)
            print(f"[?] But, What Is That?! @{e_manager.ea:x}")
            break

        e_manager.ea += instruction.size

    print(e_manager.cpu.__repr__(), e_manager.stack.__repr__())
    jumpto(e_manager.ea)
    return 0

def exec_flow_shift_msg(instruction: ida_ua.insn_t)->None:
    return print(f'jumped to @{instruction.Op1.addr:x} from @{instruction.ea:x}')

if __name__ == '__main__':
    msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(main())}')
