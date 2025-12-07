import  ida_ua, idautils, ida_allins 
from my_globals import DataTypes, __INT__
from idaapi import ea_t
from idautils import procregs

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
