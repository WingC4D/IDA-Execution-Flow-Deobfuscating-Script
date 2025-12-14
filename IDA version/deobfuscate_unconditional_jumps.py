from idaapi   import ea_t, prev_head, msg_clear, inf_is_64bit, inf_is_32bit_exactly, inf_is_16bit
from ida_xref import get_first_cref_to, get_next_cref_to
from idautils import DecodeInstruction, procregs
from enum     import Enum
from ctypes   import c_int16, c_int32, c_int64, c_uint16, c_uint32, c_uint64
from idc      import here, jumpto, BADADDR
import ida_allins, ida_bytes, ida_auto, ida_ua
# It's a skill issue lol.
__16bit__      : bool      = inf_is_16bit()
__32bit__      : bool      = inf_is_32bit_exactly()
__64bit__      : bool      = inf_is_64bit()
__JUMP_LIMIT__ : int       = 0x9
__OPER_COUNT__ : int       = 0x8

try:
    if __32bit__:
        __sBITS__     : str    = '32'
        __iBITS__     : int    = 0x20
        MSB_MASK      : int    = 0x80000000
        MAX_REG_VALUE : int    = 0xFFFFFFFF
        REG_BYTES_SIZE: int    = 4
        __INT__       : object = c_int32
        __UINT__      : object = c_uint32

    elif __64bit__:
        __sBITS__     : str    = '64'
        __iBITS__     : int    = 0x40
        MSB_MASK      : int    = 0x8000000000000000
        MAX_REG_VALUE : int    = 0xFFFFFFFFFFFFFFFF
        REG_BYTES_SIZE: int    = 8
        __INT__       : object = c_int64
        __UINT__      : object = c_uint64


    elif __16bit__:
        __sBITS__     : str    = '16'
        __iBITS__     : int    = 0x10
        MSB_MASK      : int    = 0x8000
        MAX_REG_VALUE : int    = 0xFFFF
        REG_BYTES_SIZE: int    = 2
        __INT__       : object = c_int16
        __UINT__      : object = c_uint16

    else: raise RuntimeError

except RuntimeError: exit("couldn't identify the bit-ness of the file")

__HEAP_REF__: int = MAX_REG_VALUE + 1

class SkippedDataState(Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 1
    NOT_FINISHED_IS_CODE = 2

class DataTypes(Enum):
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
                 data   : int | str | object | list | ea_t,
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

    def __repr__(self, max_length: int = 10)->str:
        repr_str: str = ''
        if isinstance(self.data, int):
            format_str: str =f'#{str(max_length)}x'
            repr_str = format(self.data, format_str)
        elif isinstance(self.data, str):
            repr_str = self.data
            length: int = len(repr_str)
            if length < max_length:
                repr_str = f"{' ' * (max_length - length)}{repr_str}"
        return f'Address: {self.addr:#8x} | Offset: {format(self.base_offset, '#6x')} | Data: {repr_str} | Size: {format(self.size, '#6x')} bytes\n'

    def is_char(self)->bool:
        return self.type == DataTypes.CHAR

    def is_string(self)->bool:
        return self.type == DataTypes.STRING

class StackFrame:
    """Stack Frame:
    A Doubly Linked List holding all data variables and their metadata
    """
    def __init__(self,
                 start_address: ea_t,
                 base_addr    : ea_t,
                 top_addr     : ea_t,
                 return_addr  : ea_t          = MAX_REG_VALUE,
                 calling_frame: object | None = None,
                 depth        : int           = 0)->None:

        self.start_addr     : ea_t                 = start_address
        self.base           : ea_t                 = base_addr
        self.top            : ea_t                 = top_addr
        self.ret_addr       : ea_t                 = return_addr
        self.data           : dict[int, StackData] = {base_addr: StackData(data=return_addr, address=top_addr, base_offset = top_addr - base_addr, size=REG_BYTES_SIZE, dt_type=DataTypes.DWORD)}
        self.last_index     : int                  = base_addr
        self.prev_frame     : StackFrame | None    = calling_frame
        self.next_frame     : StackFrame | None    = None
        self.depth          : int                  = depth
        self.top_stored_var : int                  = top_addr
        self.longest_str_len: int                  = 8

    def __repr__(self)->str:
        data_addresses: list[int]       = [data_addr for  data_addr, data_obj in self.data.items()]
        data_addresses.sort(reverse=True)
        return f"""
{'\t' * self.depth}@{self.start_addr:x} Frame:
{'\t' * self.depth}Current Base Address: {format(self.base,'#10x')}
{'\t' * self.depth}Current Stack Offset: {format(self.base - self.top, '#10x')}
{'\t' * self.depth}Current Top Address : {format(self.top, '#10x')}
{'\t' * self.depth}Stack Depth: {self.depth}
{'\t' * self.depth}Stack Data:{"{"}
{str('\t' + '\t' * self.depth)}{(str('\t' + '\t' * self.depth)).join([self.data[int(addr)].__repr__(max_length=self.longest_str_len) for addr in data_addresses if self.base >= addr >= self.top]).rstrip('\n')}
{'\t' * self.depth + '}'}"""


    @property
    def addresses(self)->list[int]:
        if not self.data: return []
        return [address for address, obj in self.data.items()]

    @property
    def top_used_addr(self)->int:
        if not self.addresses: return -1
        self.addresses.sort()
        for address in self.addresses:
            if self.base>= address >= self.top: return address

        return -1

    def add_data(self, stack_data: StackData)->None:
        if stack_data.addr < self.top:
            print(f'[!] Appended outside the frame! addr: {stack_data.addr:#x}')

        self.data[stack_data.addr] = stack_data



    def create_called_frame(self, start_address: ea_t, base_pointer, stack_pointer, ret_addr):
        self.next_frame: StackFrame = StackFrame(start_address,base_pointer, stack_pointer, ret_addr,self, self.depth + 1)

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

    def set_overflow_imul(self, arg_value_a: int, value_b: int)->None:
        self.overflow = arg_value_a * value_b  > MSB_MASK - 1 or arg_value_a * value_b < 1 - MSB_MASK

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
        self.carry    = False
        self.overflow = False
        self.sign     = False
        self.zero     = False
        self.parity   = False

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
                self.gen_registers: dict = {
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
        self.seg_registers: dict = {
            procregs.cs.reg: __UINT__()

        }
        self.flags: FlagsContext = FlagsContext()

    @property
    def reg_ax(self): return self.gen_registers[procregs.eax.reg].value

    @property
    def reg_bx(self): return self.gen_registers[procregs.ebx.reg].value

    @property
    def reg_cx(self): return self.gen_registers[procregs.ecx.reg].value

    @property
    def reg_dx(self): return self.gen_registers[procregs.edx.reg].value

    @property
    def reg_di(self): return self.gen_registers[procregs.edi.reg].value

    @property
    def reg_si(self): return self.gen_registers[procregs.esi.reg].value

    @property
    def reg_bp(self): return self.gen_registers[procregs.ebp.reg].value

    @reg_bp.setter
    def reg_bp(self,  value: int)->None:
        self.reg_bp = value
        return
    @property
    def reg_sp(self)->int: return self.gen_registers[procregs.esp.reg].value

    @reg_sp.setter
    def reg_sp(self,  value: int)->None:
        self.gen_registers[procregs.esp.reg].value = value
        return

    @property
    def reg_ip(self): return self.gen_registers[procregs.eip.reg].value

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

class EmulationManager:
    def __init__(self, starting_point: ea_t)->None:
        """
        Overview: This object is the highest level of the API, it holds (currently) 3 very important context objects.
            1. cpu    - CpuContext
            2. stack  - StackFrame
            3. helper - InstructionHelper

        Arguments:
            starting_point: ea_t -
        """
        self.cpu   : CpuContext        = CpuContext()
        self.stack : StackFrame        = StackFrame(starting_point, self.cpu.reg_bp, self.cpu.reg_sp)
        self.helper: InstructionHelper = InstructionHelper()
        self.effective_address: ea_t   = starting_point

    def __repr__(self):
        return f'{self.cpu.__repr__()}\n{self.stack.__repr__()}'

    @property
    def ea(self)->ea_t:
        return self.effective_address

    @ea.setter
    def ea(self, address: int | ea_t)->None: self.effective_address = address

    @property
    def stk_last_referenced_data(self)->StackData: return self.stack.data[self.stack.last_index]


    def extract_oper_value(self, i: int)->int    :
        """
        Overview:
            A high level method used to extract the data stored in an operand, no matter the operand type.\n

        Arguments:
            i: int: The input argument 'i', is the operand index to be used, because of the inner workings of the "InstructionHelper" class, the operands can be accessed like a normal python list. (i.e. -1 is a valid index in the list.)

        Returns:
            This method returns an integer, if the stored data is complex data type, a pointer to it will be handed back, and higher level methods/functions are meant to handle the output accordingly
        """
        try:
            if -i < len(self.helper.operands) <= i: raise IndexError
            oper_t: ida_ua.op_t = self.helper.operands[i]
            match oper_t.type:
                case ida_ua.o_imm                    : return oper_t.value
                case ida_ua.o_reg                    : return self.cpu.gen_registers[oper_t.reg].value
                case ida_ua.o_displ | ida_ua.o_phrase:
                    if oper_t.type == ida_ua.o_phrase: raise NotImplementedError
                    offset    : int =  __INT__(oper_t.addr).value
                    stack_addr: int = -1
                    match oper_t.phrase:
                        case procregs.esp.reg: stack_addr = self.cpu.reg_sp + offset
                        case procregs.ebp.reg: stack_addr = self.cpu.reg_bp + offset

                    stack_data: StackData | None = self.stack.data[stack_addr]
                    if not isinstance(stack_data, StackData): raise  NotImplementedError
                    if not isinstance(stack_data.data, int) : return self.stack.data[self.cpu.reg_bp + offset].addr
                    else                                    : return stack_data.data

            raise NotImplementedError

        except IndexError or NotImplementedError:
            exit(f'Error Code: 3\n@{self.helper.inst.ea:x}InstructionHelper.get_oper_value encountered an IndexError, with calculated index: {i:#x}')

    def handle_operation_cpu(self, oper_value: int | str | None = 1)->bool:
        org_reg_value: int = self.cpu.gen_registers[self.helper.inst.Op1.reg].value

        if self.helper.inst_type == ida_allins.NN_mov:
            if self.helper.operand_types[0] == ida_ua.o_reg:
                self.cpu.gen_registers[self.helper.operands[0].reg].value = oper_value
            print(self)
            return True

        elif self.helper.inst_type in [ida_allins.NN_inc, ida_allins.NN_dec]:
            org_carry = self.cpu.flags.carry
            self.cpu.flags.reset()
            self.cpu.flags.carry = org_carry

        else:
            self.cpu.flags.reset()
        result: int = -1
        match self.helper.inst_type:
            case ida_allins.NN_add:
                self.cpu.gen_registers[self.helper.operands[0].reg].value += oper_value
                self.cpu.flags.set_carry_add(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value)
                self.cpu.flags.set_overflow_add(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value, oper_value)

            case ida_allins.NN_and:
                self.cpu.gen_registers[self.helper.operands[0].reg].value &= oper_value

            case ida_allins.NN_cmp:
                result = __UINT__(self.cpu.gen_registers[self.helper.operands[0].reg].value - oper_value).value
                self.cpu.flags.set_carry_sub(result, org_reg_value)
                self.cpu.flags.set_overflow_sub(result, org_reg_value, oper_value)

            case ida_allins.NN_dec:
                self.cpu.gen_registers[self.helper.operands[0].reg].value -= 1
                self.cpu.flags.set_overflow_sub(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value, 1)

            case ida_allins.NN_imul:
                self.cpu.flags.reset()
                left_value : int = __INT__(self.cpu.gen_registers[self.helper.operands[0].reg].value).value
                right_value: int = __INT__(oper_value).value
                print(f"[i] iMultiplying {left_value:#x} by {right_value:#x}")
                self.cpu.gen_registers[self.helper.operands[0].reg].value = left_value * right_value
                self.cpu.flags.set_overflow_imul(__INT__(org_reg_value).value, __INT__(oper_value).value)

            case ida_allins.NN_inc:
                self.cpu.gen_registers[self.helper.operands[0].reg].value += 1
                self.cpu.flags.set_overflow_add(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value, 1)

            case ida_allins.NN_not:
                self.cpu.gen_registers[self.helper.operands[0].reg].value = ~self.cpu.gen_registers[self.helper.inst.Op1.reg].value

            case ida_allins.NN_or:
                self.cpu.gen_registers[self.helper.operands[0].reg].value |= oper_value

            case ida_allins.NN_sub:
                self.cpu.gen_registers[self.helper.operands[0].reg].value -= oper_value
                result = self.cpu.gen_registers[self.helper.operands[0].reg].value
                self.cpu.flags.set_carry_sub(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value)
                self.cpu.flags.set_overflow_sub(self.cpu.gen_registers[self.helper.operands[0].reg].value, org_reg_value, oper_value)
                """if org_reg_value - oper_value < 0:
                    self.cpu.gen_registers[self.helper.operands[0].reg].value = 0"""

            case ida_allins.NN_test:
                result = self.cpu.gen_registers[self.helper.operands[0].reg].value & oper_value

            case ida_allins.NN_xor:
                self.cpu.gen_registers[self.helper.operands[0].reg].value ^= oper_value

            case default:
                print(f'Unhandled mnemonic of const {hex(self.helper.inst_type)} @{self.ea:x}')
                return False

        if not self.helper.inst_type == ida_allins.NN_sub:
            result = self.cpu.gen_registers[self.helper.operands[0].reg].value
        self.stack.top = self.cpu.reg_sp
        self.stack.base = self.cpu.reg_bp
        self.cpu.flags.update(result)
        print(self.__repr__())
        return True


    def handle_operation_stack(self, oper_value: int, new_index: int | None = None)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        try:
            match self.helper.inst_type:
                case ida_allins.NN_mov:
                    size    = REG_BYTES_SIZE
                    dt_type = DataTypes.DWORD
                    match self.helper.operands[-1].dtype:
                        case ida_ua.dt_byte : size, dt_type = 1, DataTypes.BYTE
                        case ida_ua.dt_word : size, dt_type = 2, DataTypes.WORD
                        case ida_ua.dt_dword: size          = 4
                        case ida_ua.dt_qword: size, dt_type = 8, DataTypes.QWORD

                    if self.helper.is_in_ascii(oper_value):
                        if self.stk_last_referenced_data.is_string() or self.stk_last_referenced_data.is_char():
                            if new_index == self.stk_last_referenced_data.addr + self.stk_last_referenced_data.size:
                                self.stk_strcat(chr(oper_value), size)
                                self.stk_last_referenced_data.type = DataTypes.STRING
                                print(self.__repr__())
                                return oper_value
                        oper_value            = chr(oper_value)
                        dt_type               = DataTypes.CHAR
                        self.stack.last_index = new_index

                    elif oper_value == 0:
                        if size & 3:
                            if self.stk_last_referenced_data.is_string():
                                self.stk_last_referenced_data.size += size
                                print(self.__repr__())
                                return oper_value

                    self.stack.last_index = new_index

                    start_address: int  = 0
                    match self.helper.operands[0].reg:
                        case procregs.esp.reg: start_address = self.stack.top
                        case procregs.ebp.reg: start_address = self.stack.base
                    self.stack.add_data(StackData(oper_value, self.stack.last_index, size, self.stack.base - (start_address +  __INT__(self.helper.operands[0].addr).value), dt_type))

                case ida_allins.NN_push:
                    self.cpu.reg_sp          -= 0x4
                    self.stack.top           -= 0x4
                    self.stack.last_index     = self.stack.top
                    self.stack.top_stored_var = self.stack.top
                    self.stack.add_data(StackData(oper_value, self.stack.top, 4, self.stack.base - self.stack.top, DataTypes.DWORD))

                case ida_allins.NN_pop:
                    popped_stack_data: StackData = self.stack.data.pop(self.stack.top_stored_var)
                    self.cpu.reg_sp             += 4
                    self.stack.top              += 4
                    self.stack.last_index        = self.stack.top
                    self.stack.top_stored_var    = self.stack.top
                    popped_data: int
                    if isinstance(popped_stack_data.data  , str): popped_data = popped_stack_data.addr
                    elif isinstance(popped_stack_data.data, int): popped_data = popped_stack_data.data
                    else                                        : raise NotImplementedError
                    return popped_data

                case ida_allins.NN_popa:
                    self.stack.last_index           = self.stack.top
                    self.stack.top, self.cpu.reg_sp = self.stack.top + 0x14, self.cpu.reg_sp + 0x14


                case ida_allins.NN_pusha:
                    self.stack.last_index     = self.stack.top
                    self.stack.top           -= 0x14


                case default: raise NotImplementedError
            self.stack.top_stored_var = self.stack.top
            print(self.__repr__())
            return self.stack.last_index

        except NotImplementedError:
            exit(-1)

    def stk_strcat(self, string: str, size)->None:
        self.stk_last_referenced_data.data += string
        self.stk_last_referenced_data.size += size
        if self.stk_last_referenced_data.is_char()    : self.stk_last_referenced_data.type = DataTypes.STRING
        if len(self.stk_last_referenced_data.data) > 8: self.stack.longest_str_len         = len(self.stk_last_referenced_data.data)


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
            if not e_manager.handle_operation_cpu( e_manager.extract_oper_value(-1)):
                break

        elif e_manager.helper.is_bitwise_op():
            if not e_manager.handle_operation_cpu(e_manager.extract_oper_value(-1)):
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
                e_manager.handle_operation_cpu( e_manager.extract_oper_value(-1))

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
                e_manager.stack = e_manager.stack.create_called_frame(instruction.Op1.addr, e_manager.cpu.reg_bp, e_manager.cpu.reg_sp, instruction.ea + instruction.size)

            if not e_manager.helper.handle_forward_movement():
                print('[✕] Handle Forward Movement Failed! breaking the loop')
                break

            e_manager.ea = instruction.Op1.addr
            eval_start        = e_manager.ea
            jump_count       += 1
            continue

        elif e_manager.helper.is_arithmetic_add():
            op_value: int = e_manager.extract_oper_value(1)
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

            if not e_manager.handle_operation_cpu(op_value):
                jumpto(e_manager.ea)
                break

        elif e_manager.helper.is_arithmetic_mul():
            oper_value = e_manager.extract_oper_value(-1)
            e_manager.handle_operation_cpu(oper_value)

        elif e_manager.helper.is_non_cond_mov():
            oper_value =  e_manager.extract_oper_value(-1)
            if not e_manager.helper.validate_stack_ref():
                if instruction.Op1.type == ida_ua.o_reg:
                    e_manager.handle_operation_cpu(oper_value)

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
