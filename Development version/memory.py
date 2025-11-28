import idaapi, ida_ua, idautils, ida_allins

class Data:
    def __init__(self,
                 data   : int | str | idaapi.ea_t,
                 size   : int,
                 address: idaapi.ea_t):
        self.data = data
        self.size = size
        self.addr = address

class StackData(Data):
    def __init__(self,
                 data       : int | str | idaapi.ea_t | object | list,
                 address    : idaapi.ea_t,
                 size       : int,
                 base_offset: int)->None:
        super().__init__(data, size, address)

        self.base_offset = base_offset

class StackFrame:
    """Stack Frame:
    A Doubly Linked List holding all data variables and their metadata
    """
    def __init__(self,
                 start_address: idaapi.ea_t,
                 calling_frame: object | None = None,
                 depth        : int = 0)->None:

        self.start_addr: idaapi.ea_t       = start_address
        self.base      : int               = 0
        self.top       : int               = 0
        self.data      : dict              = {}
        self.prev_frame: StackFrame | None = calling_frame
        self.next_frame: StackFrame | None = None
        self.depth = depth

    def __repr__(self)->str:
        return f"""{'\t' * self.depth}@{self.start_addr} Frame:\n{'\t' * self.depth}
        Current Base Address: {self.start_addr + self.base}\n{'\t' * self.depth}
        Current Stack Offset: {self.top} \n{'\t' * self.depth}
        Stack Data:\n{'\n' + ('\t' * (self.depth + 1)).join([f'{str(data_addr):x}: {data_obj.data}' for data_addr, data_obj in self.data.items()])}
        """

    def add_data(self, stack_data: StackData)->None:
        if stack_data.base_offset > self.top:
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.base_offset] = stack_data

    def handle_stack_operation(self, instruction: ida_ua.insn_t, oper_value: int)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        try:
            match instruction.itype:
                case ida_allins.NN_mov:
                    if instruction.Op1.type == ida_ua.o_reg and instruction.Op1.reg == idautils.procregs.ebp.reg:
                        self.data[self.top] = StackData(oper_value, self.start_addr + self.top, 4, self.top)
                    else:
                        raise NotImplementedError

                case ida_allins.NN_push:
                    self.add_data(StackData(oper_value, self.start_addr + self.top, 4, self.top))
                    self.top += 0x4

                case ida_allins.NN_pop:
                    popped_data: int = self.data[self.top].data
                    self.top -= 0x4
                    return popped_data

                case ida_allins.NN_popa:
                    self.top -= 0x14

                case ida_allins.NN_pusha:
                    self.top += 0x14

                case ida_allins.NN_add:
                    if instruction.Op1.reg == idautils.procregs.esp.reg:
                        self.top -= oper_value

                    elif instruction.Op1.reg == idautils.procregs.ebp.reg:
                        self.base += oper_value

                case ida_allins.NN_sub:
                    if instruction.Op1.reg == idautils.procregs.esp.reg:
                        self.top += oper_value

                    elif instruction.Op1.reg == idautils.procregs.ebp.reg:
                        self.base += oper_value

                case default:
                    raise NotImplementedError

            return self.top

        except NotImplementedError:
            return -1

    def create_called_frame(self, frame_start_address: idaapi.ea_t)->object:
        self.next_frame: StackFrame = StackFrame(frame_start_address, self, self.depth + 1)
        return self.next_frame
