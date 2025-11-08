from Dependencies import idaapi, idc, idautils, ida_ua
import ctypes, enum


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

    def __repr__(self):
        print(f'Flag States:\tCF = {int(self.carry)}\tPF = {int(self.parity)}\tAF = {int(self.auxillary_carry)}\tZF = {int(self.zero)}\SF = {int(self.sign)}')

class CpuContext():
    def __init__(self):
        try:
            if __IS32__:
                uint_zero: ctypes.c_uint32 = ctypes.c_uint32(0) 

            elif __IS64__:
                uint_zero: ctypes.c_uint64 = ctypes.c_uint64(0) 

            else:
                raise ValueError
        #Registers:
            self.reg_ax = uint_zero
            self.reg_bx = uint_zero
            self.reg_cx = uint_zero
            self.reg_dx = uint_zero
            self.reg_di = uint_zero
            self.reg_si = uint_zero
            self.reg_bp = uint_zero
            self.reg_sp = uint_zero
            self.reg_ip = uint_zero
        #Flags:
            self.flags = Flags()
        
        except ValueError:
            instruction_set_msg()

    #def __repr__(self):


def main():
    effective_address  : int                 = idc.here()
    passed_instructions: list[ida_ua.insn_t] = []
    context            : CpuContext             = CpuContext()
    while True:
        instruction: ida_ua.insn_t = idautils.DecodeInstruction(effective_address)
        
        if not instruction:
            print("Not an instruction")
            break

        elif handle_instruction(instruction, passed_instructions, context):
            if passed_instructions:
                print(f'Jumping to a found handled instruction @{effective_address:x}') 
                
            break
        
        else: 
            retrive_cpu_state(instruction, context)
            effective_address += instruction.size
        
    return


def handle_instruction(instruction:ida_ua.insn_t, passed_instructions: list[ida_ua.insn_t], context: CpuContext)->bool:
    handled_instructions: list[int] = [idaapi.NN_jle, idaapi.NN_jle]
    
    try: 
        if not isinstance(instruction, ida_ua.insn_t):
            raise ValueError
    
    except ValueError: 
        print("handle_instructions must have a an instruction input of type ida_ua.insn_t")
        return False
    
    if not instruction.itype in handled_instructions:
        passed_instructions.append(instruction)
       
        return False
    idc.jumpto(instruction.ea)

    print(f'Jumped to: {instruction.ea}')

    
    
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
            
            handle_forward_address(instruction, context)
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
    

def retrive_cpu_state(instruction: ida_ua.insn_t, context: CpuContext)->None:
    handled_menmonics: list[int] = [idaapi.NN_mov, idaapi.NN_inc, idaapi.NN_dec, idaapi.NN_add, idaapi.NN_sub]
    """ 
    Idea...
    handled_operands   : list[int] = [idaapi.o_reg, idaapi.o_void]
    """
    
    if instruction.itype not in handled_menmonics:
        print(f"Found an unhandled menmonic @{instruction.ea}")
            
            
        
    if instruction.Op1.type == idaapi.o_reg or instruction.Op2.type == idaapi.o_reg:
        get_register(context, instruction)


def get_register(context: CpuContext, instruction: ida_ua.insn_t)->None:
    ida_reg_consts      : idautils._procregs                       = idautils.procregs
    register            : ctypes.c_uint32 | ctypes.c_uint64 | None = None
    non_reg_oper_indexes: list[int]                                = []
    reg_oper_indexes    : list[int]                                = []
    filled_operands     : list[ida_ua.op_t]                        = []
    
    
    for i, operand in enumerate(instruction):
        if operand.type == idaapi.o_void:
            break
        
        elif operand.type == idaapi.o_reg:
            reg_oper_indexes.append(i)
        
        else:
            non_reg_oper_indexes.append(i)
        
        filled_operands.append(operand)
    
    try:
        if len(filled_operands) > 2:
            print("UNHANLDED INSTRUCTION")
            raise NotImplementedError
    
    except:
        NotImplementedError
    
    reg_index    : int = reg_oper_indexes[0]
    non_reg_index: int = non_reg_oper_indexes[0]

    match instruction.Op1:
        case ida_reg_consts.eax:
            reg_msg("EAX", instruction)
            register = context.reg_ax
            handle_register_value(context.reg_ax, instruction, non_reg_index, context.flags)

        case ida_reg_consts.ebx:
            reg_msg("EBX", instruction)
            register = context.reg_bx
            handle_register_value(context.reg_bx, instruction, non_reg_index, context.flags)

        case ida_reg_consts.ecx:
            reg_msg("ECX", instruction)
            register = context.reg_cx
            handle_register_value(context.reg_cx, instruction, non_reg_index, context.flags)

        case ida_reg_consts.edx:
            reg_msg("EDX", instruction)
            register = context.reg_dx
            handle_register_value(context.reg_dx, instruction, non_reg_index, context.flags)


        case ida_reg_consts.edi:
            reg_msg("EDI", instruction)
            handle_register_value(context.reg_di, instruction, non_reg_index, context.flags)
            register = context.reg_di

        case ida_reg_consts.esi:
            reg_msg("ESI", instruction)
            register = context.reg_si
            handle_register_value(context.reg_si, instruction, non_reg_index, context.flags)

        case ida_reg_consts.ebp:
            reg_msg("EBP", instruction)
            register = context.reg_bp
            handle_register_value(context.reg_bp, instruction, non_reg_index, context.flags)

        case ida_reg_consts.esp:
            reg_msg("ESP", instruction)
            register = context.reg_bp
            handle_register_value(context.reg_sp, instruction, non_reg_index, context.flags)

        case defualt:
            print(f"This instrusction interacts with a register of constant: {hex(instruction[reg_oper_indexes[0]].reg)}")
        
    print(f'register current Value is {register.value:x}')

    return 


def handle_register_value(register: ctypes.c_uint32, instruction: ida_ua.insn_t, non_reg_index: int, context_flags: Flags)->None:
    match instruction.itype:    
        case idaapi.NN_mov:
            register.value = instruction[non_reg_index].value
        
        case idaapi.NN_add:
            register.value += instruction[non_reg_index].value

        case idaapi.NN_sub:
            if register.value < instruction[non_reg_index].value:
                    context_flags.zero   = True
                    register.value       = 0        
            
            else: 
                register.value -= instruction[non_reg_index].value
     

def cunt_msg(unhanled_flag: str)->None:
    print(f"This instruction uses a {unhanled_flag} flag, start handeling it ya cunt.")
    

def instruction_set_msg()->None:
    print(f'Either __IS32__ or __IS64__ must be set to "True"')
            
        
def reg_msg(register_name: str, instruction: ida_ua.insn_t)->None:
    print(f'Found a refrence to {register_name} @{instruction.ea:x}')


def handle_forward_address(instruction: ida_ua.insn_t, context: CpuContext)->None:
    print(instruction.Op1.type)
    
    match instruction.Op1.type:
        case idaapi.o_reg:
            cunt_msg("register")
            return
        
        case idaapi.o_mem:
            cunt_msg("memory")
            return
        
        case idaapi.o_near:
            to_jump_addr: ida_ua.ea_t = instruction.Op1.addr
            
            
            if idc.is_head(idaapi.get_flags(to_jump_addr)):
                cleanup_range = range(instruction.ea + instruction.size, to_jump_addr)
                
                for byte_addr in cleanup_range:
                    print(f'Undifining: {byte_addr:x}')

                idc.jumpto(to_jump_addr)
            
            print(f'Jumped to: {to_jump_addr:x}') 

            if idc.is_tail(idaapi.get_flags(to_jump_addr)) :
                pass
            else: 
                idc.jumpto(to_jump_addr)
            return
        
        case idaapi.o_far:
            cunt_msg("far")
            return
        
        case default:
            print("trace_cpu_flags::to be explored")
            return


if __name__ == "__main__":
    main()

