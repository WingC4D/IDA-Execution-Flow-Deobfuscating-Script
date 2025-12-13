import  ida_ua, ida_allins
from my_globals import DataTypes, __INT__
from idaapi import ea_t
from idautils import procregs

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

        self.start_addr     : ea_t                 = start_address
        self.base           : ea_t                 = base_addr
        self.top            : ea_t                 = top_addr
        self.data           : dict[int, StackData] = {}
        self.last_index     : int                  = base_addr
        self.prev_frame     : StackFrame | None    = calling_frame
        self.next_frame     : StackFrame | None    = None
        self.depth          : int                  = depth
        self.top_stored_var : int                  = top_addr
        self.longest_str_len: int                  = 8


    @property
    def dt_last_referenced(self)->StackData:
        return self.data[self.last_index]

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
{str('\t' + '\t' * self.depth)}{(str('\t' + '\t' * self.depth)).join([self.data[int(addr)].__repr__(max_length=self.longest_str_len) for addr in data_addresses if addr >= self.top])}
{'\t' * self.depth + '}'}"""


    def add_data(self, stack_data: StackData)->None:
        if stack_data.addr < self.top:
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.addr] = stack_data

    def handle_stack_operation(self, instruction: ida_ua.insn_t, oper_value: int | StackData, new_index: int | None = None)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        try:
            match instruction.itype:
                case ida_allins.NN_mov:
                    size: int = 4
                    dt_type = DataTypes.DWORD
                    match instruction.Op2.dtype:
                        case ida_ua.dt_byte:
                            size = 1
                        case ida_ua.dt_word:
                            size = 2
                        case ida_ua.dt_dword:
                            size = 4
                        case default:
                            exit(-5)
                    if isinstance(oper_value, int):
                        if self.is_in_ascii(oper_value):
                            if self.dt_last_referenced.is_string() or self.dt_last_referenced.is_char():
                                if new_index == self.dt_last_referenced.addr + self.dt_last_referenced.size:
                                    self.strcat(chr(oper_value), size)
                                    self.dt_last_referenced.type = DataTypes.STRING
                                    print(self)
                                    return oper_value

                            oper_value = chr(oper_value)
                            dt_type    = DataTypes.CHAR
                            self.last_index = new_index
                        elif oper_value == 0:
                            if size & 3 :
                                if self.dt_last_referenced.is_string():
                                    self.dt_last_referenced.size += size
                                    print(self)
                                    return oper_value

                        self.last_index = new_index


                    elif isinstance(oper_value, StackData):
                        oper_value  = oper_value.data
                        self.last_index = new_index

                    start: int  = 0
                    match instruction.Op1.reg:
                        case procregs.esp.reg:
                            start = self.top

                        case procregs.ebp.reg:
                            start = self.base

                    self.add_data(StackData(oper_value, self.last_index, size, self.base - (start +  __INT__(instruction.Op1.addr).value), dt_type))

                case ida_allins.NN_push:
                    self.top -= 0x4
                    self.last_index = self.top
                    self.top_stored_var = self.top
                    self.add_data(StackData(oper_value, self.top, 4, self.base - self.top, DataTypes.DWORD))

                case ida_allins.NN_pop:
                    popped_stack_data: StackData = self.data.pop(self.top_stored_var)
                    self.top += 4
                    self.last_index     = self.top
                    self.top_stored_var = self.top
                    popped_data: int
                    if isinstance(popped_stack_data.data, str):
                        popped_data =  popped_stack_data.addr

                    elif isinstance(popped_stack_data.data, int):
                        popped_data = popped_stack_data.data

                    else:
                        raise NotImplementedError

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
                    print(f'[!] Reached a Stack Substruction Operation, Substructing {oper_value:#x} @{instruction.ea:x}')
                    if instruction.Op1.reg == procregs.esp.reg:
                        self.top -= oper_value

                    elif instruction.Op1.reg == procregs.ebp.reg:
                        self.base += oper_value

                case default:
                    raise NotImplementedError
            print(self)
            return self.last_index

        except NotImplementedError:
            exit(-1)

    def create_called_frame(self, start_address: ea_t, base_pointer, stack_pointer):
        self.next_frame: StackFrame = StackFrame(start_address,base_pointer, stack_pointer,  self, self.depth + 1)

        return self.next_frame

    @staticmethod
    def is_in_ascii(candidate_value: int)->bool:
        return 0x20 <= candidate_value <= 0x80

    def strcat(self, string: str, size: int)->None:
        self.dt_last_referenced.data += string
        if self.dt_last_referenced.is_char():
            self.dt_last_referenced.type = DataTypes.STRING
        self.dt_last_referenced.size += size
        if len(self.dt_last_referenced.data) > 10:
            self.longest_str_len = len(self.dt_last_referenced.data)
