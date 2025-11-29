from idaapi import ea_t, inf_is_64bit, inf_is_32bit_exactly, inf_is_16bit, prev_head, msg_clear
from ida_xref import get_first_cref_to, get_next_cref_to
import idc, ida_allins, ida_bytes, ida_auto, ida_ua, ctypes, enum
from idautils import DecodeInstruction, procregs

# It's a skill issue lol.
__16bit__      : bool      = inf_is_16bit()
__32bit__      : bool      = inf_is_32bit_exactly()
__64bit__      : bool      = inf_is_64bit()
__JUMP_LIMIT__ : int       = 0x3
__OPER_COUNT__ : int       = 0x8
__ARITHMETIC__ : list[int] = [ida_allins.NN_add, ida_allins.NN_sub, ida_allins.NN_inc, ida_allins.NN_dec, ida_allins.NN_mul, ida_allins.NN_div, ida_allins.NN_mov]
__COMPARATIVE__: list[int] = [ida_allins.NN_cmp, ida_allins.NN_test]
__BITWISE_OPS__: list[int] = [ida_allins.NN_and, ida_allins.NN_or, ida_allins.NN_xor]
__STACK_OPS__  : list[int] = [ida_allins.NN_push, ida_allins.NN_pop, ida_allins.NN_pusha, ida_allins.NN_popa]

try:
    if __32bit__:
        __sBITS__    : str = '32'
        __iBITS__    : int = 32
        MSB_MASK     : int = 0x80000000
        __UINT__     : object = ctypes.c_uint32
        MAX_REG_VALUE: int = 0xFFFFFFFF

    elif __64bit__:
        __sBITS__     : str = '64'
        __iBITS__     : int = 64
        MSB_MASK      : int = 0x8000000000000000
        __UINT__      : object = ctypes.c_uint64
        MAX_REG_VALUE : int = 0xFFFFFFFFFFFFFFFF
        REG_BYTES_SIZE: int = 8

    elif __16bit__:
        __sBITS__    : str = '16'
        __iBITS__    : int = 16
        MSB_MASK     : int = 0x8000
        __UINT__     : object = ctypes.c_uint16
        MAX_REG_VALUE: int = 0xFFFF
    else: raise RuntimeError
except RuntimeError:
    print("couldn't identify the bit-ness of the file")
    exit(-1)

class SkippedDataState(enum.Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 11111
    NOT_FINISHED_IS_CODE = 2

class DataTypes(enum.Enum):
    BYTE    = 0x1
    WORD    = 0x2
    DWORD   = 0x4
    QWORD   = 0x8
    POINTER = 0xC
    TEB     = 0xF0
    PEB     = 0xFFA

class Data:
    def __init__(self,
                 data   : int | str | object | list| ea_t,
                 size   : int,
                 address: ea_t,
                 dt_type: DataTypes):
        self.data = data
        self.size = size
        self.addr = address
        self.type = dt_type

class StackData(Data):
    def __init__(self,
                 data       : int | str | object | list | ea_t,
                 address    : ea_t,
                 size       : int,
                 base_offset: int,
                 dt_type    : DataTypes
                 )->None:
        super().__init__(data, size, address, dt_type)

        self.base_offset = base_offset

    def __repr__(self): return f'{self.base_offset:x8}: {self.data} | {self.size} bytes\n'

class StackFrame:
    """Stack Frame:
    A Doubly Linked List holding all data variables and their metadata
    """
    def __init__(self,
                 start_address: ea_t,
                 calling_frame: object | None = None,
                 depth        : int = 0)->None:

        self.start_addr    : ea_t              = start_address
        self.base          : ea_t              = 0
        self.top           : ea_t              = 0
        self.data          : dict              = {}
        self.prev_frame    : StackFrame | None = calling_frame
        self.next_frame    : StackFrame | None = None
        self.depth         : int               = depth
        self.top_stored_var: ea_t              = 0

    def __repr__(self)->str:
        normal_new_line: str = '\t' * self.depth
        return f"""
{normal_new_line}@{self.start_addr:x} Frame:
{normal_new_line}Current Base Address: {(self.start_addr + self.base):x}
{normal_new_line}Current Stack Offset: {self.top:x}
{normal_new_line}Stack Depth: {self.depth}
{normal_new_line}Stack Data:{"{"}
{'\t' + (normal_new_line + '\t').join([data_obj.__repr__() for data_addr, data_obj in self.data.items()])}
{'}'}"""

    def add_data(self, stack_data: StackData)->None:
        if stack_data.base_offset > self.top:
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.base_offset] = stack_data
        self.top_stored_var = self.top

    def handle_stack_operation(self, instruction: ida_ua.insn_t, oper_value: int)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        try:
            match instruction.itype:
                case ida_allins.NN_mov:
                    if instruction.Op1.type == ida_ua.o_reg:
                        reg = instruction.Op1.reg
                    elif instruction.Op1.type == ida_ua.o_displ:
                        reg = instruction.Op1.phrase
                    else:
                        raise NotImplementedError

                    if reg == procregs.ebp.reg:
                        self.data[0 + instruction.Op1.addr] = StackData(oper_value, self.start_addr + self.top, 4, self.top, DataTypes.DWORD)
                    elif reg == procregs.esp.reg:
                        self.data[self.top + instruction.Op1.addr] = StackData(oper_value, self.start_addr + self.top, 4, self.top, DataTypes.DWORD)
                    else:
                        raise NotImplementedError

                case ida_allins.NN_push:
                    self.top += 0x4
                    self.add_data(StackData(oper_value, self.start_addr + self.top, 4, self.top, DataTypes.DWORD))

                case ida_allins.NN_pop:
                    popped_data: int = self.data.pop(self.top_stored_var).data
                    self.top -= 0x4
                    return popped_data

                case ida_allins.NN_popa:
                    self.top -= 0x14

                case ida_allins.NN_pusha:
                    self.top += 0x14

                case ida_allins.NN_add:
                    if instruction.Op1.reg == procregs.esp.reg:
                        self.top -= oper_value

                    elif instruction.Op1.reg == procregs.ebp.reg:
                        self.base += oper_value

                case ida_allins.NN_sub:
                    if instruction.Op1.reg == procregs.esp.reg:
                        self.top += oper_value

                    elif instruction.Op1.reg == procregs.ebp.reg:
                        self.base += oper_value

                case default:
                    raise NotImplementedError
            print(self)
            return self.top

        except NotImplementedError:
            exit(-1)

    def create_called_frame(self, frame_start_address: ea_t):
        self.next_frame: StackFrame = StackFrame(frame_start_address, self, self.depth + 1)
        return self.next_frame

class FlagsContext:
    """Flags Context:\n
    This class holds context to all (currently 32bit) flags used by conditional execution opcodes
    """
    def __init__(self)->None:
        self.sign           : bool = False
        self.carry          : bool = False
        self.zero           : bool = False
        self.parity         : bool = False
        self.overflow       : bool = False
        self.direction      : bool = False
        self.auxiliary_carry: bool = False
        self.trap           : bool = False
        self.interrupt      : bool = False

    def __repr__(self)->str: return f"""Flag States:
\tZF = {int(self.zero)}\tPF = {int(self.parity)}\tAF = {int(self.auxiliary_carry)}
\tOF = {int(self.overflow)}\tSF = {int(self.sign)}\tDF = {int(self.direction)}
\tCF = {int(self.carry)}\tTF = {int(self.trap)}\tIF = {int(self.interrupt)}"""

    @staticmethod
    def _check_sign(value)->bool: return value & MSB_MASK != 0

    def set_sign(self, result: int)->None:
        self.sign = result & MSB_MASK != 0

    def set_carry_add(self, result: int, org_value_a: int, )->None:
        self.carry = result < org_value_a

    def set_carry_sub(self, result: int, org_value_a: int, )->None:
        self.carry = result > org_value_a

    def set_overflow_add(self, result: int, org_value_a: int, value_b: int)->None:
        if self._check_sign(org_value_a) == self._check_sign(value_b):
            self.overflow = self._check_sign(value_b) != self._check_sign(result)
        else:
            self.overflow = False

    def set_overflow_sub(self, result: int, org_value_a: int, value_b: int)->None:
        if self._check_sign(org_value_a) != self._check_sign(value_b):
            self.overflow = self._check_sign(value_b) == self._check_sign(result)
        else:
            self.overflow = False

    def set_parity(self, result: int)->None:
        least_significant_byte: int = result & 0xFF
        bits_set_to_1         : int = 0
        curr_bit              : int = 1
        while curr_bit <= 0x80:

            if curr_bit & least_significant_byte:
                bits_set_to_1 += 1

            curr_bit <<= 1
        self.parity = bits_set_to_1 % 2 == 0

    def reset(self)->None:
        self.carry, self.overflow, self.sign, self.zero, self.parity = False, False, False, False, False

    def update(self, result: int)->None:
        self.zero  = result == 0
        self.set_parity(result)
        self.set_sign(result)

class CpuContext:
    """CPU Context Class:\n
    - This class holds context to all registers & flags (currently of a 32bit processor)\n

    Data Members:\n
    1. registers:\n
    - type: dict\n
    - data: ctypes unsigned int in the cpu's bit size\n
    - indexing: procregs.REG.reg\n
    2. flags:\n
    - type: FlagsContext
    - details: see Flags context
    """

    def __init__(self):
        try:
            if __32bit__:
                self.registers: dict = {
                    procregs.eax.reg: __UINT__(0),
                    procregs.ebx.reg: __UINT__(0),
                    procregs.ecx.reg: __UINT__(0),
                    procregs.edx.reg: __UINT__(0),
                    procregs.edi.reg: __UINT__(0),
                    procregs.esi.reg: __UINT__(0),
                    procregs.ebp.reg: __UINT__(0),
                    procregs.esp.reg: __UINT__(0),
                    procregs.eip.reg: __UINT__(0)
                }
            else:
                raise NotImplementedError
        except NotImplementedError:
            exit(f"Currently only handles 32bit processors")

        self.flags: FlagsContext = FlagsContext()

    @property
    def reg_ax(self): return self.registers[procregs.eax.reg].value

    @property
    def reg_bx(self): return self.registers[procregs.ebx.reg].value

    @property
    def reg_cx(self): return self.registers[procregs.ecx.reg].value

    @property
    def reg_dx(self): return self.registers[procregs.edx.reg].value

    @property
    def reg_di(self): return self.registers[procregs.edi.reg].value

    @property
    def reg_si(self): return self.registers[procregs.esi.reg].value

    @property
    def reg_bp(self): return self.registers[procregs.ebp.reg].value

    @property
    def reg_sp(self)->int: return self.registers[procregs.esp.reg].value

    @property
    def reg_ip(self): return self.registers[procregs.eip.reg].value

    def __repr__(self)->str: return f"""CPU Context:
- Architecture: {__sBITS__}bit Intel || AMD\n\n- Integer Registers:\n\tReg_AX: {hex(self.reg_ax)}
\tReg_BX: {hex(self.reg_bx)}
\tReg_CX: {hex(self.reg_cx)}
\tReg_DX: {hex(self.reg_dx)}
\tReg_DI: {hex(self.reg_di)}
\tReg_SI: {hex(self.reg_si)}
\tReg_BP: {hex(self.reg_bp)}
\tReg_SP: {hex(self.reg_sp)}
\tReg_IP: {hex(self.reg_ip)}
	
- {self.flags}\n"""

    def update_regs_n_flags(self, instruction: ida_ua.insn_t)->bool:
        if instruction.Op2.type == ida_ua.o_reg:
            right_oper_value: int = self.registers[instruction.Op2.reg].value
        else:
            right_oper_value = instruction.Op2.value

        org_reg_value: int = self.registers[instruction.Op1.reg].value

        if instruction.itype == ida_allins.NN_mov:
            self.registers[instruction.Op1.reg].value = right_oper_value
            return True

        elif instruction in [ida_allins.NN_inc, ida_allins.NN_dec]:
            org_carry = self.flags.carry
            self.flags.reset()
            self.flags.carry = org_carry

        else:
            self.flags.reset()

        match instruction.itype:
            case ida_allins.NN_add:
                self.registers[instruction.Op1.reg].value += right_oper_value
                self.flags.set_carry_add(self.registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_add(self.registers[instruction.Op1.reg].value, org_reg_value,right_oper_value)

            case ida_allins.NN_and:
                self.registers[instruction.Op1.reg].value &= right_oper_value

            case ida_allins.NN_cmp:
                comp_result = __UINT__(self.registers[instruction.Op1.reg].value - right_oper_value)
                self.flags.set_carry_sub(comp_result.value, org_reg_value)
                self.flags.set_overflow_sub(comp_result.value, org_reg_value, right_oper_value)
                self.flags.update(comp_result.value)
                return True

            case ida_allins.NN_dec:
                self.registers[instruction.Op1.reg].value -= 1
                self.flags.set_overflow_sub(self.registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_inc:
                self.registers[instruction.Op1.reg].value += 1
                self.flags.set_overflow_add(self.registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_or:
                self.registers[instruction.Op1.reg].value |= right_oper_value

            case ida_allins.NN_sub:
                self.registers[instruction.Op1.reg].value -= right_oper_value
                self.flags.set_carry_sub(self.registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_sub(self.registers[instruction.Op1.reg].value, org_reg_value, right_oper_value)

            case ida_allins.NN_test:
                test_result = self.registers[instruction.Op1.reg].value & right_oper_value
                self.flags.update(test_result)
                return True

            case ida_allins.NN_xor:
                self.registers[instruction.Op1.reg].value ^= right_oper_value

            case default:
                print(f'Unhandled mnemonic of const {hex(instruction.itype)} @{instruction.ea:x}')

                return False

        self.flags.update(self.registers[instruction.Op1.reg].value)
        return True

    def eval_cond_jump(self, instruction_type: int)->bool:
        match instruction_type:
            case ida_allins.NN_jo   : return self.flags.overflow
            case ida_allins.NN_js   : return self.flags.sign
            case ida_allins.NN_jl   : return self.flags.sign != self.flags.overflow
            case ida_allins.NN_jno  : return not self.flags.overflow
            case ida_allins.NN_jns  : return not self.flags.sign
            case ida_allins.NN_jcxz : return not self.reg_cx & 0xFFFF
            case ida_allins.NN_jecxz: return not self.reg_cx & 0xFFFFFFFF
            case ida_allins.NN_jrcxz: return not self.reg_cx & 0xFFFFFFFFFFFFFFFF
            case ida_allins.NN_jp   | ida_allins.NN_jpe : return self.flags.parity
            case ida_allins.NN_jbe  | ida_allins.NN_jna : return self.flags.carry or self.flags.zero
            case ida_allins.NN_jge  | ida_allins.NN_jnl : return self.flags.sign == self.flags.overflow
            case ida_allins.NN_jle  | ida_allins.NN_jng : return self.flags.sign != self.flags.overflow or self.flags.zero
            case ida_allins.NN_jnz  | ida_allins.NN_jne : return not self.flags.zero
            case ida_allins.NN_jnp  | ida_allins.NN_jpo : return not self.flags.parity
            case ida_allins.NN_jg   | ida_allins.NN_jnle: return not self.flags.zero and self.flags.sign == self.flags.overflow
            case ida_allins.NN_jnbe | ida_allins.NN_ja  : return not self.flags.carry and not self.flags.zero
            case ida_allins.NN_jz   | ida_allins.NN_je  | ida_allins.NN_jnge: return self.flags.zero
            case ida_allins.NN_jb   | ida_allins.NN_jc  | ida_allins.NN_jnae: return self.flags.carry
            case ida_allins.NN_jnb  | ida_allins.NN_jnc | ida_allins.NN_jae : return not self.flags.carry
            case default: return False

class InstructionHelper:
    def __init__(self, instruction: ida_ua.insn_t | None = None):
        self.inst         : ida_ua.insn_t     | None = instruction
        self.operands     : list[ida_ua.op_t]        = []
        self.operand_types: list[int]                = []

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

            if second_referer != idc.BADADDR and second_referer != idc.BADADDR != self.inst.ea:
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
        first_xref: int
        while current_address <= self.inst.Op1.addr:
            first_xref = get_first_cref_to(current_address)
            if first_xref in [idc.BADADDR, 0]:
                current_address += 1
                continue
            elif get_next_cref_to(current_address, first_xref) != idc.BADADDR: return SkippedDataState.FINISHED_IS_NOT_JUNK, current_address
            elif ida_bytes.is_code(ida_bytes.get_flags(current_address))     : return SkippedDataState.NOT_FINISHED_IS_CODE, current_address
            print(f'[i] adding 1, Current Address {current_address:x}, Destination Address: {self.inst.Op1.addr}')
            current_address += 1
        return SkippedDataState.FINISHED_IS_JUNK, current_address

    def contains_displ(self):
        self.validate_operands()
        return ida_ua.o_displ in self.operand_types

    def contains_imm( self)->bool:
        self.validate_operands()
        return ida_ua.o_imm  in self.operand_types

    def contains_near(self)->bool:
        self.validate_operands()
        return ida_ua.o_imm in self.operand_types

    def contains_phrase(self)->bool:
        self.validate_operands()
        return ida_ua.o_phrase in self.operand_types

    def contains_reg(self)->bool:
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

    def helper_delta(self)->ea_t:
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

def main(effective_address: ea_t       = idc.here(),
         context          : CpuContext        = CpuContext(),
         jump_count       : int               = 0,
         helper           : InstructionHelper = InstructionHelper())->int:
    stack      : StackFrame    = StackFrame(effective_address)
    eval_start : ea_t          = effective_address
    instruction: ida_ua.insn_t
    while True:
        context.registers[procregs.eip.reg].value = effective_address

        if jump_count >= __JUMP_LIMIT__:
            break
        instruction = DecodeInstruction(effective_address)
        if not instruction:
            print(f'[✕] Not code @{effective_address:x}, breaking the loop.')
            break
        helper.set_instruction(instruction)

        if instruction.itype in [ida_allins.NN_retn, ida_allins.NN_retf]:
            idc.jumpto(effective_address)
            break

        elif instruction.itype in __ARITHMETIC__:
            if instruction.Op1.type == ida_ua.o_reg:
                if instruction.Op1.reg in [procregs.ebp.reg, procregs.esp.reg]:
                    stack.handle_stack_operation(instruction, context.registers[instruction.Op1.reg].value)
                    if instruction.Op1.type == instruction.Op2.type:
                        if instruction.Op2.reg == procregs.esp.reg:
                            stack.create_called_frame(eval_start)
                        elif instruction.Op2.type == ida_ua.o_imm:
                            stack.handle_stack_operation(instruction, instruction.Op2.value)
                        print(stack)
            if not context.update_regs_n_flags(instruction):
                idc.jumpto(effective_address)
                break

        elif instruction.itype in __STACK_OPS__:
            if instruction.Op1.type == ida_ua.o_imm:
                right_oper_value: int = instruction.Op1.value

            elif instruction.Op1.type == ida_ua.o_reg:
                right_oper_value: int = context.registers[instruction.Op1.reg].value

            elif instruction.Op1.type == ida_ua.o_displ:

                if instruction.Op1.phrase == procregs.ebp.reg:
                    right_oper_value = stack.data[instruction.Op1.addr].data

                elif instruction.Op1.phrase == procregs.esp.reg:
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
    msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(main())}')
