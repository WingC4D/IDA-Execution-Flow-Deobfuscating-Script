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

     start_address - """
    def __init__(self,
                 start_address: idaapi.ea_t,
                 sp_delta     : int           = 0,
                 bp_delta     : int           = 0,
                 calling_frame: object | None = None)->None:

        self.start     : idaapi.ea_t       = start_address
        self.base      : int               = bp_delta
        self.top       : int               = sp_delta
        self.data      : dict              = {}
        self.prev_frame: StackFrame | None = calling_frame
        self.next_frame: StackFrame | None = None

    def add_data(self, stack_data: StackData)->None:
        if stack_data.base_offset > self.top:
            print(f'[!] Appended outside the frame!')

        self.data[stack_data.base_offset] = stack_data

    def handle_stack_operation_imm(self, instruction: ida_ua.insn_t, oper_value: int)->int:
        """This method handles the "StackFrame" class' data members when a PUSH or a POP operation is identified.\n
        This method returns the current stack offset to help evaluate the SP correctness."""
        try:
            match instruction.itype:
                case ida_allins.NN_mov:
                    if instruction.Op1.type == ida_ua.o_reg and instruction.Op1.reg == idautils.procregs.esp.reg:
                        if instruction.Op2.type == ida_ua.o_reg and instruction.Op2.reg == idautils.procregs.ebp.reg:
                            self.create_called_frame(idautils.DecodePreviousInstruction(instruction.ea))

                case ida_allins.NN_push:
                    self.top += 0x4
                    if instruction.Op1 == ida_ua.o_imm:
                        self.add_data(StackData(instruction.Op1.value, self.base + self.top, 4, self.top))

                case ida_allins.NN_pop:
                    self.top -= 0x4

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

    def create_called_frame(self, frame_start_address: idaapi.ea_t, sp_delta: int = 0, bp_delta: int = 0)->None:
        self.next_frame            = StackFrame(frame_start_address, sp_delta, bp_delta)
        self.next_frame.prev_frame = self