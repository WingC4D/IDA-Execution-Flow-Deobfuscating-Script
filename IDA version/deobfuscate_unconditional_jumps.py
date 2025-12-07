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

try:
    if __32bit__:
        __sBITS__    : str = '32'
        __iBITS__    : int = 32
        MSB_MASK     : int = 0x80000000
        __INT__      : object = ctypes.c_int32
        __UINT__     : object = ctypes.c_uint32
        MAX_REG_VALUE: int = 0xFFFFFFFF

    elif __64bit__:
        __sBITS__     : str = '64'
        __iBITS__     : int = 64
        MSB_MASK      : int = 0x8000000000000000
        __INT__       : object = ctypes.c_int64
        __UINT__      : object = ctypes.c_uint64
        MAX_REG_VALUE : int = 0xFFFFFFFFFFFFFFFF
        REG_BYTES_SIZE: int = 8

    elif __16bit__:
        __sBITS__    : str = '16'
        __iBITS__    : int = 16
        MSB_MASK     : int = 0x8000
        __INT__      : object = ctypes.c_uint16
        __UINT__     : object = ctypes.c_uint16
        MAX_REG_VALUE: int = 0xFFFF

    else: raise RuntimeError
except RuntimeError:
    print("couldn't identify the bit-ness of the file")
    exit(-1)
__HEAP_REF__ = MAX_REG_VALUE + 1

class SkippedDataState(enum.Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 1
    NOT_FINISHED_IS_CODE = 2

class DataTypes(enum.Enum):
    BYTE    = 0x1
    WORD    = 0x2
    DWORD   = 0x4
    QWORD   = 0x8
    POINTER = 0xC
    CHAR    = 0x10
    STRING  = 0x20
    TEB     = 0x100
    PEB     = 0x200

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

    def __repr__(self):
        if isinstance(self.data, int):
            self.data = hex(self.data)
        return f'Offset: {hex(self.base_offset)} | Data: {self.data} | Size: {hex(self.size)} bytes\n'

    def is_char(self)->bool:
        return self.type == DataTypes.CHAR

    def is_string(self)->bool: return self.type == DataTypes.STRING

class StackFrame:
    """Stack Frame:
    A Doubly Linked List holding all data variables and their metadata
    """
    def __init__(self,
                 start_address: ea_t,
                 base_addr    : ea_t,
                 top_addr     : ea_t,
                 calling_frame: object | None = None,
                 depth        : int           = 0)->None:

        self.start_addr    : ea_t                 = start_address
        self.base          : ea_t                 = base_addr
        self.top           : ea_t                 = top_addr
        self.data          : dict[int, StackData] = {}
        self.last_index    : int                  = base_addr
        self.prev_frame    : StackFrame | None    = calling_frame
        self.next_frame    : StackFrame | None    = None
        self.depth         : int                  = depth
        self.top_stored_var: int                  = top_addr

    def __eq__(self, other):
        self.start_addr     = other.start_addr
        self.base           = other.base
        self.top            = other.top
        self.data           = other.data
        self.prev_frame     = other.prev_frame
        self.next_frame     = other.next_frame
        self.depth          = other.depth
        self.top_stored_var = other.top_stored_var

    @property
    def dt_last_referenced(self)->StackData:
        return self.data[self.last_index]

    def __repr__(self)->str:
        data_addresses: list[int]       = [data_addr for  data_addr, data_obj in self.data.items()]
        data_addresses.sort(reverse=True)
        return f"""
{'\t' * self.depth}@{self.start_addr:x} Frame:
{'\t' * self.depth}Current Base Address: {self.base:x}
{'\t' * self.depth}Current Stack Offset: {self.top:x}
{'\t' * self.depth}Stack Depth: {self.depth}
{'\t' * self.depth}Stack Data:{"{"}
{'\t' + ('\t' * self.depth + '\t').join([self.data[int(addr)].__repr__() for addr in data_addresses])}
{'\t' * self.depth + '}'}"""


    def add_data(self, stack_data: StackData)->None:
        if stack_data.base_offset < self.top:
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.base_offset] = stack_data

    def handle_stack_operation(self, instruction: ida_ua.insn_t, oper_value: int | StackData, new_index: int | None = None)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        print("stack ops")

        try:
            match instruction.itype:
                case ida_allins.NN_mov:
                    size = 4
                    dt_type = DataTypes.DWORD

                    if isinstance(oper_value, int):
                        if self.is_in_ascii(oper_value):
                            oper_char = chr(oper_value)
                            if self.dt_last_referenced.is_string() or self.dt_last_referenced.is_char():

                                self.strcat(oper_char)
                                print(self)
                                return oper_value

                            else:
                                oper_value = oper_char
                                size = 1
                                dt_type = DataTypes.CHAR
                                self.last_index = new_index

                    elif isinstance(oper_value, StackData):
                        oper_value  = oper_value.data
                        self.last_index = new_index

                    self.add_data(StackData(oper_value, self.last_index, size, self.base +  __INT__(instruction.Op1.addr).value, dt_type))

                case ida_allins.NN_push:
                    self.last_index = self.top
                    self.top -= 0x4
                    self.top_stored_var = self.top
                    self.add_data(StackData(oper_value, int(self.start_addr + self.top), 4, self.top, DataTypes.DWORD))

                case ida_allins.NN_pop:
                    popped_stack_data: StackData = self.data.pop(self.top_stored_var)
                    popped_data: int
                    if isinstance(popped_stack_data.data, str):
                        popped_data =  popped_stack_data.addr

                    elif isinstance(popped_stack_data.data, int):
                        popped_data = popped_stack_data.data

                    else:
                        raise NotImplementedError

                    self.last_index = self.top
                    self.top += 0x4
                    self.top_stored_var = self.top
                    return popped_data

                case ida_allins.NN_popa:
                    self.last_index = self.top
                    self.top += 0x14
                    self.top_stored_var = self.top

                case ida_allins.NN_pusha:
                    self.last_index = self.top
                    self.top -= 0x14
                    self.top_stored_var = self.top

                case ida_allins.NN_add:
                    if instruction.Op1.reg == procregs.esp.reg:
                        self.top += oper_value

                    elif instruction.Op1.reg == procregs.ebp.reg:
                        self.base += oper_value

                case ida_allins.NN_sub:
                    print(f'[!] Reached a Stack Substruction Operation, Substructing {oper_value} @{instruction.ea:x}')
                    if instruction.Op1.reg == procregs.esp.reg:
                        self.top -= oper_value

                    elif instruction.Op1.reg == procregs.ebp.reg:
                        self.base += oper_value

                case default:
                    raise NotImplementedError
            print(self)
            return self.top

        except NotImplementedError:
            exit(-1)

    def create_called_frame(self, start_address: ea_t, base_pointer, stack_pointer):
        self.next_frame: StackFrame = StackFrame(start_address,base_pointer, stack_pointer,  self, self.depth + 1)

        return self.next_frame

    @staticmethod
    def is_in_ascii(candidate_value: int)->bool:
        return 0x20 <= candidate_value <= 0x80

    def strcat(self, string: str)->None:
        self.dt_last_referenced.data += string
        self.dt_last_referenced.size += 1
        if self.dt_last_referenced.is_char():
            self.dt_last_referenced.type = DataTypes.STRING

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
    def _check_sign(value)->bool:
        return value & MSB_MASK != 0

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
                    procregs.ebp.reg: __UINT__(0x100000),
                    procregs.esp.reg: __UINT__(0x100000),
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
            if instruction.Op1.type == ida_ua.o_reg:
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
        return False

    def eval_cond_mov(self, instruction_type: int)->bool:
        match instruction_type:
            case ida_allins.NN_cmovbe: return self.flags.carry or self.flags.zero
            case ida_allins.NN_cmovg : return self.flags.sign == self.flags.overflow and not self.flags.zero
            case ida_allins.NN_cmovge: return self.flags.sign == self.flags.overflow
            case ida_allins.NN_cmovl : return self.flags.sign != self.flags.overflow
            case ida_allins.NN_cmovle: return self.flags.sign != self.flags.overflow or self.flags.zero
            case ida_allins.NN_cmovb : return self.flags.carry
            case ida_allins.NN_cmovo : return self.flags.overflow
            case ida_allins.NN_cmovp : return self.flags.parity
            case ida_allins.NN_cmovs : return self.flags.sign
            case ida_allins.NN_cmovz : return self.flags.zero
            case ida_allins.NN_cmovnz: return not self.flags.zero
            case ida_allins.NN_cmovns: return not self.flags.sign
            case ida_allins.NN_cmovnp: return not self.flags.parity
            case ida_allins.NN_cmovno: return not self.flags.overflow
            case ida_allins.NN_cmovnb: return not self.flags.carry
            case ida_allins.NN_cmova : return not self.flags.carry and not self.flags.zero
        return False

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

    def is_arithmetic(self)->bool:
        return self.inst.itype in [ida_allins.NN_add, ida_allins.NN_div, ida_allins.NN_dec, ida_allins.NN_imul, ida_allins.NN_inc, ida_allins.NN_sub]

    def is_bitwise_op(self)->bool:
        return self.inst.itype in [ida_allins.NN_and, ida_allins.NN_or, ida_allins.NN_xor, ida_allins.NN_not]

    def is_comparative(self)->bool:
        return self.inst.itype in [ida_allins.NN_cmp, ida_allins.NN_test]

    def is_stack_op(self)->bool:
        return self.inst.itype in [ida_allins.NN_push, ida_allins.NN_pop, ida_allins.NN_pusha, ida_allins.NN_popa]

    def is_call_inst(self)->bool:
        return ida_allins.NN_call <= self.inst.itype <= ida_allins.NN_callni

    def is_cond_jump(self)->bool:
        return ida_allins.NN_ja <= self.inst.itype <= ida_allins.NN_jz

    def is_cond_mov(self)->bool:
        return ida_allins.NN_cmova <= self.inst.itype <= ida_allins.NN_cmovz

    def is_junk_condition(self, eval_start: ea_t)->bool:
        curr_helper  = InstructionHelper(DecodeInstruction(prev_head(self.inst.ea, 0)))
        current_eval_instruction: ida_ua.insn_t = DecodeInstruction(eval_start)
        curr_helper.validate_operands()

        if (curr_helper.is_arithmetic()  and curr_helper.inst.Op1.type == ida_ua.o_reg
        or  curr_helper.is_comparative() and ida_ua.o_phrase not in curr_helper.operand_types):

            while current_eval_instruction.ea <= self.inst.ea:

                if current_eval_instruction.itype == ida_allins.NN_mov:
                    if current_eval_instruction.Op1.reg  == curr_helper.inst.Op1.reg:
                        if current_eval_instruction.Op2.type == ida_ua.o_imm:
                            return True

                current_eval_instruction = DecodeInstruction(current_eval_instruction.ea + current_eval_instruction.size)

        return False

    def is_non_cond_mov(self)->bool:
        if not ida_allins.NN_mov <= self.inst.itype <= ida_allins.NN_movzx:
            if not ida_allins.NN_movaps <= self.inst.itype <= ida_allins.NN_movups:
                if not ida_allins.NN_movapd <= self.inst.itype <= ida_allins.NN_movupd:
                    if not ida_allins.NN_movddup <= self.inst.itype <= ida_allins.NN_movsxd:
                        return  False
        return True

    def is_non_cond_jump(self)->bool:
        return ida_allins.NN_jmp <= self.inst.itype <= ida_allins.NN_jmpshort

    def validate_operands(self)->bool:
        if not self.operand_types:
            if not self.operands:
                self.get_operand_objects()
                if not len(self.operands):
                    return False
            self.get_operands_types()
        return True

    def set_instruction(self, instruction: ida_ua.insn_t)->None:
        self.inst           = instruction
        self.operands       = []
        self. operand_types = []

    def get_oper_value(self, operand_index: int, context: CpuContext, stack: StackFrame)-> int | str | None:
        self.validate_operands()
        try:
            if len(self.operands) <= operand_index:
                raise IndexError
            operand: ida_ua.op_t = self.inst[operand_index]
            match operand.type:
                case ida_ua.o_imm  : return operand.value
                case ida_ua.o_reg  : return context.registers[operand.reg].value
                case ida_ua.o_displ:
                    offset =  __INT__(operand.addr).value
                    match operand.reg:
                        case procregs.esp.reg: return stack.data[context.reg_sp + offset].data
                        case procregs.ebp.reg: return stack.data[context.reg_bp + offset].data

                    return __HEAP_REF__

                case ida_ua.o_phrase:
                    match operand.reg:
                        case procregs.esp.reg: return stack.data[stack.top].data
                        case procregs.ebp.reg: return stack.data[stack.base].data

                    return __HEAP_REF__

        except IndexError:
            exit(f'Error Code: 3\n@{self.inst.ea:x}InstructionHelper.get_oper_value encountered an IndexError, with calculated index: {hex(operand_index)}')

    def retrieve_stack_addr(self, context:CpuContext)->int:
        if not self.validate_stack_regs_op():
            return 0
        match self.operand_types[0]:
            case ida_ua.o_reg:
                return context.registers[self.inst[0].reg].value

            case ida_ua.o_phrase:
                return self.inst[0].phrase

            case ida_ua.o_displ:
                return context.registers[self.inst[0].phrase].value + __INT__(self.inst[0].addr).value

        return -1

    def validate_stack_regs_op(self)->bool:
        if not self.validate_operands():
            print(f'[x] Failed to validate Operands @{self.inst.ea:x}')
            return False

        match self.operand_types[0]:
            case ida_ua.o_reg:
                return self.operands[0].reg in [procregs.esp.reg, procregs.ebp.reg]

            case ida_ua.o_phrase | ida_ua.o_displ:
                return self.operands[0].phrase in [procregs.esp.reg, procregs.ebp.reg]

        return False

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
