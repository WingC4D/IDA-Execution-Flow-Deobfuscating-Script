import idaapi
import idc
import idautils
import ida_ua
import ctypes
__IS32__ = True
__IS64__ = False
idaapi.msg_clear()
class Flags():
    def __init__(self):
        self.carry          : bool = False
        self.parity         : bool = False
        self.auxillary_carry: bool = False
        self.zero           : bool = False
        self.sign           : bool = False

class Register():
    def __init__(self, name: str):
        self.name: str = name
        try:
            if __IS32__:
                self.value: ctypes.c_uint32 = ctypes.c_uint32(0)
            elif __IS64__:
                self.value: ctypes.c_uint64 = ctypes.c_uint64(0)
            else:
                raise ValueError 
    
        except ValueError:
            instruction_set_msg()
        ida_const:int = 0


class Registers_x86():
    def __init__(self):
        self.eax: Register = Register('eax')
        self.ebx: Register = Register('ebx')
        self.ecx: Register = Register('ecx')
        self.edx: Register = Register('edx')
        self.edi: Register = Register('edi')
        self.esi: Register = Register('esi')
        self.ebp: Register = Register('ebp')
        self.esp: Register = Register('esp')
        self.eip: Register = Register('eip')


class Cpu():
    def __init__(self):
        try:
            if __IS32__:
                regs: Registers_x86 = Registers_x86()
                
                self.reg_ax
                self.reg_bx
                self.reg_cx
                self.reg_dx
                self.reg_di
                self.reg_si
                self.reg_bp
                self.reg_sp
                self.reg_ip
            
            elif __IS64__:

                self.reg_ax
                self.reg_bx
                self.reg_cx
                self.reg_dx
                self.reg_di
                self.reg_si
                self.reg_bp
                self.reg_sp
                self.reg_ip
            
            else:
                raise ValueError
        
        except ValueError:
            instruction_set_msg()

        self.flag_carry          : bool = False
        self.flag_parity         : bool = False
        self.flag_auxilliry_carry: bool = False
        self.flag_sign           : bool = False
        self.flag_zero           : bool = False


def main():
    effective_address  : int                 = idc.here()
    passed_instructions: list[ida_ua.insn_t] = []
    
    while True:
        instruction: ida_ua.insn_t = idautils.DecodeInstruction(effective_address)
        
        if not instruction:
            print("Not an instruction")
            break

        elif handle_instructions(instruction, passed_instructions):
            if passed_instructions:
                print(f'Jumping to a found handled instruction @{effective_address:x}') 
                idc.jumpto(effective_address)
            
            break
        
        else: 
            effective_address += instruction.size

    if passed_instructions:
        print(f'Found unhandled instructions at these addresses:')
        [print(f'{inst.ea:x}') for inst in passed_instructions]
    
    return


def handle_instructions(instruction:ida_ua.insn_t, passed_instructions: list[ida_ua.insn_t])->bool:
    handled_instructions: list[int] = [idaapi.NN_jle, idaapi.NN_jle]
    
    try: isinstance(instruction, ida_ua.insn_t)
    except ValueError: 
        print("handle_instructions must have a an instruction input of type ida_ua.insn_t")
        return
    
    if not instruction.itype in handled_instructions:
        passed_instructions.append(instruction)
       
        return False

    flags: Flags = trace_cpu_flags(passed_instructions)
    
    match (instruction.itype):
        case idaapi.NN_jz:
            return True
        
        case idaapi.NN_jnz:
            return True
        
        case idaapi.NN_je: 
            return True
        
        case idaapi.NN_jne:
            return True
        
        case idaapi.NN_jle: 
            return True
        
        case idaapi.NN_jbe: 
            return True
        
        case idaapi.NN_jb: 
            return True
        
        case idaapi.NN_call: 
            return True
        
        case defualt:
            passed_instructions.append(instruction)
            return False        
    

def trace_cpu_flags(passed_instructions: list[ida_ua.insn_t])->Flags:
    if not passed_instructions:
        print("trace_cpu_flags::No passed_instructions argument passed in, nothing to trace.")
        return Flags()

    handled_instruction: list[int] = [idaapi.NN_mov, idaapi.NN_inc, idaapi.NN_dec, idaapi.NN_add, idaapi.NN_sub]
    """ 
    Idea...
    handled_operands   : list[int] = [idaapi.o_reg, idaapi.o_void]
    """
    for instruction in reversed(passed_instructions):
        if instruction.itype not in handled_instruction:
            print(f"Found an unhandled instruction @{instruction.ea}")
            continue
        if instruction.Op1.type != idaapi.o_reg:
            print("This handled instruction is not interacting with a register")
            continue
        print(f"This instrusction interacts with a register of constant: {hex(instruction.Op1.reg)}")

def handle_forward_address(instruction: ida_ua.insn_t):
    try: isinstance(instruction, ida_ua.insn_t)
    except ValueError: 
        print("trace_cpu_flags must have a an instruction input of type ida_ua.insn_t")
        return Flags()
    match instruction.Op1.type:
        case idaapi.o_reg:
            cunt_msg("register")
            return
        
        case idaapi.o_mem:
            cunt_msg("memory")
            return
        
        case idaapi.o_near:
            cunt_msg("near")
            return
        
        case idaapi.o_far:
            cunt_msg("far")
            return
        
        case default:
            print("trace_cpu_flags::to be explored")
            return



def cunt_msg(unhanled_flag: str)->None:
    print(f"This instruction uses a {unhanled_flag} flag, start handeling it ya cunt.")
    return

def instruction_set_msg()->None:
    print(f'Either __IS32__ or __IS64__ must be set to "True"')

if __name__ == "__main__":
    main()

