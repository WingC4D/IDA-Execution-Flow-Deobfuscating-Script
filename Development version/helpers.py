import ida_ua, ida_bytes, ida_allins
from idaapi import ea_t, prev_head
from  idc import BADADDR
from idautils import DecodeInstruction, procregs
from my_globals import SkippedDataState, __INT__, __OPER_COUNT__
from ida_xref import get_first_cref_to, get_next_cref_to
from cpu import CpuContext

class InstructionHelper:
    def __init__(self, instruction: ida_ua.insn_t | None = None):
        self.inst         : ida_ua.insn_t     | None = instruction
        self.operands     : list[ida_ua.op_t]        = []
        self.operand_types: list[int]                = []
    @property
    def inst_type(self):
        return self.inst.itype

    def are_skipped_instructions_junk(self)->bool:
        addresses_delta: ea_t = self.helper_delta()

        if not addresses_delta:
            return False

        elif addresses_delta > 0x800:
            print(f'[i] Addresses Delta @{self.inst.ea:x} is shifting forward the execution flow more than 2048 bytes, this is not a junk execution flow shift!')
            return False

        eval_instruction: ida_ua.insn_t = self.inst
        next_addr       : ea_t          = self.inst.ea + self.inst.size

        while next_addr <= self.inst.Op1.addr:
            second_referer: ea_t = get_next_cref_to(eval_instruction.ea, get_first_cref_to(eval_instruction.ea))

            if second_referer != BADADDR and second_referer != BADADDR != self.inst.ea:
                return False

            elif not ida_bytes.is_code(ida_bytes.get_flags(next_addr)):
                result, passed_bytes  = self.are_skipped_unexplored_bytes_junk()
                match result:
                    case SkippedDataState.FINISHED_IS_NOT_JUNK: return False
                    case SkippedDataState.FINISHED_IS_JUNK    : return True
                    case SkippedDataState.NOT_FINISHED_IS_CODE:
                        next_addr += passed_bytes
                        continue

            eval_instruction = DecodeInstruction(next_addr)
            next_addr        = eval_instruction.ea + eval_instruction.size

        return True

    def are_skipped_unexplored_bytes_junk(self)->tuple:
        current_address: ea_t = self.inst.ea
        first_xref     : int
        while current_address <= self.inst.Op1.addr:
            first_xref = get_first_cref_to(current_address)
            if first_xref in [BADADDR, 0]:
                current_address += 1
                continue

            elif get_next_cref_to(current_address, first_xref) != BADADDR:
                return SkippedDataState.FINISHED_IS_NOT_JUNK, current_address

            elif ida_bytes.is_code(ida_bytes.get_flags(current_address)): return SkippedDataState.NOT_FINISHED_IS_CODE, current_address

            print(f'[i] adding 1, Current Address {current_address:x}, Destination Address: {self.inst.Op1.addr}')
            current_address += 1

        return SkippedDataState.FINISHED_IS_JUNK, current_address

    def contains_displ(self)->bool : return ida_ua.o_displ in self.operand_types
    def contains_imm( self)->bool  : return ida_ua.o_imm  in self.operand_types
    def contains_near(self)->bool  : return ida_ua.o_imm in self.operand_types
    def contains_phrase(self)->bool: return ida_ua.o_phrase in self.operand_types

    def contains_reg(self)->bool: return ida_ua.o_reg  in self.operand_types

    def get_operand_objects(self)->list[ida_ua.op_t]:
        for i in range(__OPER_COUNT__):
            if self.inst[i].type == ida_ua.o_void:
                break
            self.operands.append(self.inst[i])
        return self.operands

    def get_operands_types(self)->list[int]:
        if not self.operands:
            self.get_operand_objects()
        self.operand_types = [operand.type for operand in self.operands]
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

    def helper_delta(self)->ea_t:
        addresses_delta: ea_t = self.inst.Op1.addr - self.inst.size - self.inst.ea
        if 0 > addresses_delta:
            print(f'[i] Addresses Delta @{self.inst.ea:x} has been found to be negative!')
            return 0
        return addresses_delta

    def is_arithmetic_add(self)->bool: return self.inst_type in [ida_allins.NN_add, ida_allins.NN_sub, ida_allins.NN_dec, ida_allins.NN_inc]

    def is_arithmetic_mul(self): return self.inst_type in [ida_allins.NN_div, ida_allins.NN_mul, ida_allins.NN_idiv, ida_allins.NN_imul]

    def is_bitwise_op(self)->bool: return self.inst.itype in [ida_allins.NN_and, ida_allins.NN_or, ida_allins.NN_xor, ida_allins.NN_not]

    def is_comparative(self)->bool: return self.inst.itype in [ida_allins.NN_cmp, ida_allins.NN_test]

    def is_stack_op(self)->bool: return self.inst.itype in [ida_allins.NN_push, ida_allins.NN_pop, ida_allins.NN_pusha, ida_allins.NN_popa]

    def is_call_inst(self)->bool: return ida_allins.NN_call <= self.inst.itype <= ida_allins.NN_callni

    def is_cond_jump(self)->bool: return ida_allins.NN_ja <= self.inst.itype <= ida_allins.NN_jz

    def is_cond_mov(self)->bool: return ida_allins.NN_cmova <= self.inst.itype <= ida_allins.NN_cmovz

    def is_junk_condition(self, eval_start: ea_t)->bool:
        prev_inst_helper        : InstructionHelper  = InstructionHelper(DecodeInstruction(prev_head(self.inst.ea, 0)))
        current_eval_instruction: ida_ua.insn_t      = DecodeInstruction(eval_start)
        prev_inst_helper.validate_operands()
        if (prev_inst_helper.is_arithmetic_add()  and prev_inst_helper.inst[0].type == ida_ua.o_reg
        or  prev_inst_helper.is_comparative() and ida_ua.o_phrase not in prev_inst_helper.operand_types):

            while current_eval_instruction.ea <= self.inst.ea:

                if current_eval_instruction.itype == ida_allins.NN_mov:
                    if current_eval_instruction[0].reg  == prev_inst_helper.inst[0].reg:
                        if current_eval_instruction.Op2.type == ida_ua.o_imm: return True

                current_eval_instruction = DecodeInstruction(current_eval_instruction.ea + current_eval_instruction.size)

        return False

    def is_non_cond_mov(self)->bool:
        if not ida_allins.NN_mov <= self.inst_type <= ida_allins.NN_movzx:
            if not ida_allins.NN_movaps <= self.inst_type <= ida_allins.NN_movups:
                if not ida_allins.NN_movapd <= self.inst_type <= ida_allins.NN_movupd:
                    if not ida_allins.NN_movddup <= self.inst_type <= ida_allins.NN_movsxd: return  False
        return True

    def is_non_cond_jump(self)->bool: return ida_allins.NN_jmp <= self.inst_type <= ida_allins.NN_jmpshort

    def validate_operands(self)->bool:
        if not self.operand_types:
            if not self.operands:
                self.get_operand_objects()
                if not len(self.operands): return False
            self.get_operands_types()
        return True

    def set_instruction(self, instruction: ida_ua.insn_t)->None:
        self.inst           = instruction
        self.operands       = []
        self. operand_types = []
        self.validate_operands()

    def retrieve_stack_addr(self, context: CpuContext, i: int)->int:
        match self.operand_types[i]:
            case ida_ua.o_phrase | ida_ua.o_displ: return context.gen_registers[self.operands[i].phrase].value + __INT__(self.inst[0].addr).value
        return -1

    def validate_stack_ref(self)->bool:
        reg_const: int = -1
        match self.operand_types[0]:
            case ida_ua.o_phrase | ida_ua.o_displ: return self.operands[0].phrase in [procregs.esp.reg, procregs.ebp.reg]
            case default: return False


    @staticmethod
    def is_in_ascii(candidate_value: int)->bool:
        return 0x20 <= candidate_value <= 0x80
