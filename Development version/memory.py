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
{str('\t' + '\t' * self.depth)}{(str('\t' + '\t' * self.depth)).join([self.data[int(addr)].__repr__(max_length=self.longest_str_len) for addr in data_addresses if self.base >= addr >= self.top])}
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
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.addr] = stack_data



    def create_called_frame(self, start_address: ea_t, base_pointer, stack_pointer):
        self.next_frame: StackFrame = StackFrame(start_address,base_pointer, stack_pointer,  self, self.depth + 1)

        return self.next_frame