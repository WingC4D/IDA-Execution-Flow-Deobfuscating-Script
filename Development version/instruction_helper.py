import ida_ua, idc, ida_bytes, ida_xref, ida_allins
from idaapi import ea_t, prev_head
from idautils import DecodeInstruction
from my_globals import SkippedDataState, __ARITHMETIC__, __COMPARATIVE__, __OPER_COUNT__
from ida_xref import get_first_cref_to, get_next_cref_to
class InstructionHelper:
    def __init__(self, instruction: ida_ua.insn_t | None = None):
        self.inst         : ida_ua.insn_t     | None = instruction
        self.operands     : list[ida_ua.op_t]        = []
        self.operand_types: list[int]                = []

    def are_skipped_instructions_junk(self)->bool:
        addresses_delta: int = self.helper_delta()

        if not addresses_delta:
            return False

        elif addresses_delta > 0x800:
            print(f'[i] Addresses Delta @{self.inst.ea:x} is shifting forward the execution flow more than 2048 bytes, this is not a junk execution flow shift!')
            return False

        eval_instruction: ida_ua.insn_t = self.inst
        next_addr       : ea_t          = self.inst.ea + self.inst.size

        while next_addr <= self.inst.Op1.addr:
            second_referer: ea_t = ida_xref.get_next_cref_to(eval_instruction.ea, ida_xref.get_first_cref_to(eval_instruction.ea))

            if second_referer != idc.BADADDR and second_referer != idc.BADADDR != self.inst.ea:
                return False

            elif not ida_bytes.is_code(ida_bytes.get_flags(next_addr)):

                match self.are_skipped_unexplored_bytes_junk():

                    case SkippedDataState.FINISHED_IS_NOT_JUNK: return False
                    case SkippedDataState.FINISHED_IS_JUNK    : return True
                    case SkippedDataState.NOT_FINISHED_IS_CODE: continue

            eval_instruction = DecodeInstruction(next_addr)
            next_addr        = eval_instruction.ea + eval_instruction.size

        return True

    def are_skipped_unexplored_bytes_junk(self)->SkippedDataState:
        current_address: ea_t = self.inst.ea
        first_xref: int
        while current_address <= self.inst.Op1.addr:

            first_xref  = get_first_cref_to(current_address)
            current_address += 1

            if not first_xref:
                print(f'[i] Skipped unexplored byte @{current_address:x} is not referenced by ANY code')
                continue

            if get_next_cref_to(current_address, first_xref) != idc.BADADDR: return SkippedDataState.FINISHED_IS_NOT_JUNK
            elif ida_bytes.is_code(ida_bytes.get_flags(current_address))   : return SkippedDataState.NOT_FINISHED_IS_CODE

        return SkippedDataState.FINISHED_IS_JUNK

    def contains_imm( self)->bool:
        self.validate_operands()
        return ida_ua.o_imm  in self.operand_types

    def contains_near(self)->bool:
        self.validate_operands()
        return ida_ua.o_imm in self.operand_types

    def contains_reg( self)->bool:
        self.validate_operands()
        return ida_ua.o_reg  in self.operand_types

    def get_operand_objects(self)->list[ida_ua.op_t]:
        for i in range(__OPER_COUNT__):
            if self.inst[i].type == ida_ua.o_void:
                break
            self.operands.append(self.inst[i])
        return self.operands

    def get_operands_types(self)->list[int]:
        if not self.operands:
            self.get_operand_objects()
        self.operand_types = [operand.type for operand in self.get_operand_objects()]
        return self.operand_types

    def handle_forward_movement(self)->bool:
        if not self.are_skipped_instructions_junk():
            print(f'[i] Data skipped from @{self.inst.ea:x} to @{self.inst.Op1.addr:x} has been found to be NOT junk!')
            return True

        print(f'[✓] Data skipped from @{self.inst.ea:x} to @{self.inst.Op1.addr:x} has been found to be junk!')

        if ida_bytes.del_items(self.inst.ea + self.inst.size, ida_bytes.DELIT_SIMPLE,self.inst.Op1.addr - self.inst.size - self.inst.ea):
            print(f'[✓] Undefined data from @{(self.inst.ea + self.inst.size):x} to @{self.inst.Op1.addr:x}')

            if not ida_bytes.is_code(ida_bytes.get_flags(self.inst.Op1.addr)):
                print(f'[i] Byte @{self.inst.Op1.addr:x} has been found to be undefined, attempting to create a new instruction...')
                new_len: int = ida_ua.create_insn(self.inst.Op1.addr)

                if new_len:
                    print(f'[✓] Created a new instruction @{self.inst.Op1.addr:x}')
                    return True

                else:
                    print(f'[✕] Failed to undefined data from @{(self.inst.ea + self.inst.size):x} to {self.inst.Op1.addr:x}')

            else:
                print(f'[✓] @{self.inst.Op1.addr:x} has been found to be a Head of type Code!')
                return True

        else:
            print(f'[✕] Failed to undefined data from @{(self.inst.ea + self.inst.size):x} to {self.inst.Op1.addr:x}')

        return False

    def helper_delta(self)->int:
        addresses_delta: ea_t = self.inst.Op1.addr - self.inst.size - self.inst.ea
        if 0 > addresses_delta:
            print(f'[i] Addresses Delta @{self.inst.ea:x} has been found to be negative!')
            return 0
        return addresses_delta

    def is_cond_jump(self)->bool:
        return ida_allins.NN_ja <= self.inst.itype <= ida_allins.NN_jz

    def is_junk_condition(self, eval_start: ea_t)->bool:
        previous_instruction    : ida_ua.insn_t = DecodeInstruction(prev_head(self.inst.ea, 0))
        current_eval_instruction: ida_ua.insn_t = DecodeInstruction(eval_start)
        first_eval_op_one       : ida_ua.op_t   = previous_instruction.Op1
        first_eval_op_two       : ida_ua.op_t   = previous_instruction.Op2

        if (previous_instruction.itype in __ARITHMETIC__  and first_eval_op_one.type == ida_ua.o_reg
        or  previous_instruction.itype in __COMPARATIVE__ and first_eval_op_two.type != ida_ua.o_phrase):

            while current_eval_instruction.ea <= self.inst.ea:

                if (current_eval_instruction.Op2.type == ida_ua.o_imm
                and current_eval_instruction.Op1.reg  == first_eval_op_one.reg
                and current_eval_instruction.itype    == ida_allins.NN_mov): return True

                current_eval_instruction = DecodeInstruction(current_eval_instruction.ea + current_eval_instruction.size)

        return False

    def is_non_cond_jump(self)->bool: return ida_allins.NN_jmp <= self.inst.itype <= ida_allins.NN_jmpshort

    def validate_operands(self)->bool:
        if not self.operand_types:
            if not self.operands:
                self.get_operand_objects()
            if len(self.operands):
                return False
            self.get_operands_types()
        return True

    def set_instruction(self, instruction: ida_ua.insn_t)->None:
        self.inst           = instruction
        self.operands       = []
        self. operand_types = []


"""
        elif ida_allins.NN_mov <= instruction.itype <=ida_allins.NN_movsx:
            if instruction.Op1.type in [ida_ua.o_displ, ida_ua.o_phrase]:
                reg = instruction.Op1.phrase
            elif instruction.Op1.type == ida_ua.o_reg:
                reg = instruction.Op1.reg
            else: break
            context.update_regs_n_flags(instruction)
            if reg in [procregs.esp.reg, procregs.ebp.reg]:
                if instruction.Op2.type == ida_ua.o_imm:
                    value: int = instruction.Op2.value
                elif instruction.Op2.type == ida_ua.o_reg:
                    value: int = context.registers[instruction.Op2.type].value
                else: break
                stack.handle_stack_operation(instruction, value)
        """