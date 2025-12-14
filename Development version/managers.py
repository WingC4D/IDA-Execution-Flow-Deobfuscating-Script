from memory     import StackFrame, StackData
from cpu        import CpuContext
from helpers    import InstructionHelper
from my_globals import __INT__, __UINT__, DataTypes, REG_BYTES_SIZE
from idaapi     import ea_t
from idautils   import procregs
import ida_ua,  ida_allins

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

"""case ida_allins.NN_add:
        if instruction.Op1.reg == procregs.esp.reg:
            self.top += oper_value

        elif instruction.Op1.reg == procregs.ebp.reg:
            self.base += oper_value

    case ida_allins.NN_sub:
        print(f'[!] Reached a Stack Substruction Operation, Substructing {oper_value:#x} @{instruction.ea:x}')
        if instruction.Op1.reg == procregs.esp.reg:
            self.top -= oper_value

        elif instruction.Op1.reg == procregs.ebp.reg:
            self.base += oper_value """