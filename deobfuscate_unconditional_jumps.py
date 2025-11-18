#It's a skill issue lol.

from Dependencies import idaapi, idc, idautils, ida_ua, ida_bytes, ida_xref
import ctypes

idaapi.msg_clear()

__IS32__      : bool = True
__IS64__      : bool = False
__JUMP_COUNT__: int  = 0x2
__OPER_COUNT__: int  = 0x8 
__ARITHMETIC__: list[int] = [idaapi.NN_add, idaapi.NN_sub, idaapi.NN_inc, idaapi.NN_dec, idaapi.NN_mul, idaapi.NN_div]

class FlagsContext:
    def __init__(self):
        self.zero           : bool = False
        self.parity         : bool = False #PF (bit 2): Parity flag - Set if the least-significant byte of the result contains an even number of bits set to 1; cleared otherwise.
        self.auxiliary_carry: bool = False
        self.overflow       : bool = False
        self.direction      : bool = False
        self.sign           : bool = False
        self.carry          : bool = False        
        self.trap           : bool = False
        self.interrupt      : bool = False

    def __repr__(self)-> str: return f'Flag States:\n\t ZF = {int(self.zero)} \t PF = {int(self.parity)} \t AF = {int(self.auxiliary_carry)}\n\t OF = {int(self.overflow)} \t SF = {int(self.sign)} \t DF = {int(self.direction)}\n\t CF = {int(self.carry)} \t TF = {int(self.trap)} \t IF = {int(self.interrupt)}'

    def reset(self)->None: 
        self.carry, self.overflow, self.sign, self.zero, self.parity = False, False, False, False, False

    def set_sign(self, result: int)->None: 
        self.sign = result & MSB_MASK != 0
        
    def set_carry_add(self, org_value_a: int, result: int)->None: 
        self.carry = result < org_value_a

    def set_carry_sub(self, org_value_a: int, result: int)->None: 
        self.carry = result > org_value_a

    def set_overflow_add(self, org_value_a: int, value_b: int, result: int)->None: 
        if self._check_sign(org_value_a) == self._check_sign(value_b):
            self.overflow = self._check_sign(value_b) != self._check_sign(result)
        else:
            self.overflow = False

    def set_overflow_sub(self, org_value_a: int, value_b: int, result: int)->None:
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

    def update(self, result: int)->None:
        self.zero = result == 0
        self.set_parity(result)
        self.set_sign(result)

    @staticmethod
    def _check_sign(value)->bool: return value & MSB_MASK != 0
            
def instruction_set_msg()->None: return print(f'Either __IS32__ or __IS64__ must be set to "True"')

try: 
    if   __IS32__: 
        MAX_REG_VALUE: int    = 0x00000000FFFFFFFF
        BITS         : str    = '32'
        __UINT__     : object = ctypes.c_uint32
        MSB_MASK     : int    = 0x0000000080000000
    elif __IS64__:
        MAX_REG_VALUE: int    = 0xFFFFFFFFFFFFFFFF 
        BITS         : str    = '64'
        __UINT__     : object = ctypes.c_uint64
        MSB_MASK     : int    = 0x8000000000000000
    else:
        raise ValueError
except ValueError: 
    instruction_set_msg()
    exit(-1)

class CpuContext:
    def __init__(self):       
    #Registers:
        self.registers: dict = {
            idautils.procregs.eax.reg: __UINT__(0),
            idautils.procregs.ebx.reg: __UINT__(0),
            idautils.procregs.ecx.reg: __UINT__(0),
            idautils.procregs.edx.reg: __UINT__(0),
            idautils.procregs.edi.reg: __UINT__(0),
            idautils.procregs.esi.reg: __UINT__(0),
            idautils.procregs.ebp.reg: __UINT__(0),
            idautils.procregs.esp.reg: __UINT__(0),
            idautils.procregs.eip.reg: __UINT__(0)
        }
    #Flags:
        self.flags: FlagsContext = FlagsContext()     
    
    @property
    def reg_ax(self):
        return self.registers[idautils.procregs.eax.reg].value
    @property
    def reg_bx(self):
        return self.registers[idautils.procregs.ebx.reg].value
    @property
    def reg_cx(self):
        return self.registers[idautils.procregs.ecx.reg].value
    @property
    def reg_dx(self):
        return self.registers[idautils.procregs.edx.reg].value
    @property
    def reg_di(self):
        return self.registers[idautils.procregs.edi.reg].value
    @property
    def reg_si(self):
        return self.registers[idautils.procregs.esi.reg].value
    @property
    def reg_bp(self):
        return self.registers[idautils.procregs.ebp.reg].value
    @property
    def reg_sp(self):
        return self.registers[idautils.procregs.esp.reg].value
    @property
    def reg_ip(self):
        return self.registers[idautils.procregs.eip.reg].value
    
    def __repr__(self)->str: 
        return f'############\n\nCPU Context:\n\n- Architecture:\n\t {BITS}bit Intel || AMD\n\n- Integer Registers:\n\t Reg_AX: {hex(self.reg_ax)}\n\t Reg_BX: {hex(self.reg_bx)}\n\t Reg_CX: {hex(self.reg_cx)}\n\t Reg_DX: {hex(self.reg_dx)}\n\t Reg_DI: {hex(self.reg_di)}\n\t Reg_SI: {hex(self.reg_si)}\n\t Reg_BP: {hex(self.reg_bp)}\n\t Reg_SP: {hex(self.reg_sp)}\n\t Reg_IP: {hex(self.reg_ip)}\n\n- {self.flags}\n\n############'

def main(effective_address: idaapi.ea_t = idc.here(), context: CpuContext  = CpuContext())->None:
    jump_count      : int         = 0
    iteration_count : int         = 1
    frame_start     : idaapi.ea_t = effective_address
    while True:
        instruction       : ida_ua.insn_t     = idautils.DecodeInstruction(effective_address)
        context.registers[idautils.procregs.eip.reg].value = effective_address 
        
        if not instruction or not ida_bytes.is_code(ida_bytes.get_flags(effective_address)) or jump_count >= __JUMP_COUNT__:
            if not instruction:
                print(f'Not an instruction @{effective_address:x}') 
                break
            
            elif jump_count >= __JUMP_COUNT__:
                print(f'Taken {__JUMP_COUNT__} jumps, all finished.')
                break
            
            print(f'Not code @{effective_address:x}')
            break
        
        elif instruction.itype == idaapi.NN_call:
            execution_flow_shift_msg(instruction, context)
            effective_address = instruction.Op1.addr
            idc.jumpto(instruction.Op1.addr)
            jump_count += 1
            continue

        elif is_non_cond_jump(instruction):
            execution_flow_shift_msg(instruction, context)
            effective_address, frame_start = instruction.Op1.addr, instruction.Op1.addr
            idc.jumpto(instruction.Op1.addr)
            jump_count += 1
            continue
        
        elif is_cond_jump(instruction):
            if eval_cond_jump(instruction.itype, context.flags):
                
                if is_junk_condition(effective_address, frame_start): 
                    print(f'[i] Conditional jump @{effective_address:x} of type: {instruction.itype:x} has been found to be junk!')
                else: 
                    print(f'[!] Conditional jump @{effective_address:x} of type: {instruction.itype:x} has been found NOT to be junk!')
                if is_skipped_data_junk(instruction, instruction.Op1.addr): 
                    print(f'[i] Data skipped from @{effective_address:x} to @{instruction.Op1.addr:x} has been found to be junk!')
                else: 
                    print(f'[!] Data skipped from @{effective_address:x} to @{instruction.Op1.addr:x} has been found NOT to be junk!') 
                idc.jumpto(instruction.Op1.addr)
                effective_address = instruction.Op1.addr
                frame_start = instruction.Op1.addr
                jump_count += 1
                continue
                
        elif is_arithmetic(instruction) and instruction.Op2.type == ida_ua.o_imm:
            context.flags.reset()
            update_reg_imm(instruction, context)
        
        #print(f'\nStep: {iteration_count}\n{context.flags}')
        iteration_count += 1
        effective_address += instruction.size 
    return

def update_reg_imm(instruction: ida_ua.insn_t, context    : CpuContext)->bool:
    operands: list[ida_ua.op_t] = get_operand_objects(instruction)
    try: 
        if len(operands) > 2: raise NotImplementedError
    except NotImplementedError: 
        print(f'Found {len(operands)} instructions, Stopping.')
        return False
        
    return handle_register_value(context.registers[instruction.Op1.reg], instruction, context.flags) 

def handle_register_value(register: ctypes.c_uint32, instruction: ida_ua.insn_t, context_flags: FlagsContext)->None:
    org_reg_value: int = register.value
    match instruction.itype:    
        case idaapi.NN_mov: register.value  = instruction.Op2.value
        
        case idaapi.NN_add: 
            register.value += instruction.Op2.value
            context_flags.set_carry_add(org_reg_value, register.value)
            context_flags.set_overflow_add(org_reg_value, instruction.Op2.value, register.value)

        case idaapi.NN_sub:
            register.value -= instruction.Op2.value
            context_flags.set_carry_sub   (org_reg_value, register.value)
            context_flags.set_overflow_sub(org_reg_value, instruction.Op2.value, register.value)

        case idaapi.NN_dec:
            register.value -= 1        
            context_flags.set_overflow_sub(org_reg_value, 1, register.value)

        case idaapi.NN_inc:
            register.value += 1
            context_flags.set_overflow_add(org_reg_value, 1, register.value)
        
        case default:
            print(f'Unhandled mnemonic of const {hex(instruction.itype)}')
    context_flags.update(context_flags.registers[instruction.Op1.reg].value)        
    return

def handle_forward_movement(instruction: ida_ua.insn_t)->bool: return idc.jumpto(instruction.Op1.addr)

def unhandled_jump_msg(jump_name: str)->bool: print(f'[!] Hit an unhandled jump of type {jump_name} returning False'); return False

def reg_msg(register_name: str, instruction: ida_ua.insn_t)->None: return print(f'Found a reference to {register_name} @{instruction.ea:x}')

def cunt_msg(unhandled_flag: str)->None: return print(f'This instruction uses a {unhandled_flag}, start handling it ya cunt.')

def execution_flow_shift_msg(instruction: ida_ua.insn_t, context: CpuContext)->None:
    if instruction.itype != idaapi.NN_call: 
        return print(f'jumped to {instruction.Op1.addr:x} from {instruction.ea:x}\n\n{context}')
    else:
        return print(f'Called @{instruction.Op1.addr:x} from {instruction.ea:x}\n\n{context}')

def contains_imm( operand_types: list[int])->bool: return ida_ua.o_imm  in operand_types

def contains_near(operand_types: list[int])->bool: return idaapi.o_near in operand_types 

def contains_reg( operand_types: list[int])->bool: return ida_ua.o_reg  in operand_types

def eval_cond_jump(instruction_type: int, context: CpuContext)->bool:
    match instruction_type:
        case idaapi.NN_jo   : return context.flags.overflow
        
        case idaapi.NN_js   : return context.flags.sign
        
        case idaapi.NN_jl   : return context.flags.sign != context.flags.overflow
        
        case idaapi.NN_jno  : return not context.flags.overflow
        
        case idaapi.NN_jns  : return not context.flags.sign
        
        case idaapi.NN_ja   : return not context.flags.carry and not context.flags.overflow
        
        case idaapi.NN_jnbe : return not context.flags.carry and not context.flags.zero
        
        case idaapi.NN_jcxz : return not context.reg_cx & 0xFFFF
        
        case idaapi.NN_jecxz: return not context.reg_cx & 0xFFFFFFFF
        
        case idaapi.NN_jrcxz: return not context.reg_cx & 0xFFFFFFFFFFFFFFFF
        
        case idaapi.NN_jp   | idaapi.NN_jpe : return context.flags.parity
        
        case idaapi.NN_jbe  | idaapi.NN_jna : return context.flags.carry or context.flags.zero

        case idaapi.NN_jge  | idaapi.NN_jnl : return context.flags.sign == context.flags.overflow
        
        case idaapi.NN_jle  | idaapi.NN_jng : return context.flags.sign != context.flags.overflow or context.flags.zero
        
        case idaapi.NN_jnp  | idaapi.NN_jpo : return not context.flags.parity   
        
        case idaapi.NN_jnz  | idaapi.NN_jne : return not context.flags.zero
        
        case idaapi.NN_jg   | idaapi.NN_jnle: return not context.flags.zero and context.flags.sign == context.flags.overflow

        case idaapi.NN_jz   | idaapi.NN_je  | idaapi.NN_jnge: return context.flags.zero  
        
        case idaapi.NN_jb   | idaapi.NN_jc  | idaapi.NN_jnae: return context.flags.carry
        
        case idaapi.NN_jnb  | idaapi.NN_jnc | idaapi.NN_jae : return not context.flags.carry
        
def get_operands_types(operand_objects: list[ida_ua.op_t] | None = None, instruction: ida_ua.insn_t | None = None)->list[int]:
    try:
        if not operand_objects:
            if not instruction: raise TypeError
            else: operand_objects = get_operand_objects(instruction)
        return [operand.type for operand in operand_objects]
    
    except TypeError:
        print("[x] get_operand_types::Error! No input was passed")
        return []
    
def get_operand_objects(instruction: ida_ua.insn_t)->list[ida_ua.op_t]:
    result: list[ida_ua.op_t] = []
    for i in range (__OPER_COUNT__):
        if instruction[i].type == idaapi.o_void: break
        result.append(instruction[i])
    return result 

def is_arithmetic(instruction: ida_ua.insn_t)->bool: return instruction.itype in __ARITHMETIC__

def is_cond_jump(instruction: ida_ua.insn_t)->bool: return idaapi.NN_ja  <= instruction.itype <= idaapi.NN_jz

def is_junk_condition(effective_address: idaapi.ea_t, eval_start: idaapi.ea_t)->bool:
    last_instruction : ida_ua.insn_t = idautils.DecodeInstruction(idaapi.prev_head(effective_address, 0))
    curr_instruction : ida_ua.insn_t = idautils.DecodeInstruction(eval_start)
    case_operand     : ida_ua.op_t   = last_instruction.Op1
    if last_instruction.Op1.type == ida_ua.o_reg and last_instruction.itype in __ARITHMETIC__ or last_instruction.itype == idaapi.NN_cmp and last_instruction.Op2 != idaapi.o_phrase:
        const: int = case_operand.reg
        while curr_instruction.ea <= effective_address:
            if (curr_instruction.itype == idaapi.NN_mov
                and curr_instruction.Op1.reg == const
                and curr_instruction.Op2.type == idaapi.o_imm):
                return True
            curr_instruction = idautils.DecodeInstruction(curr_instruction.ea + curr_instruction.size)
            
    return False

def is_non_cond_jump( instruction: ida_ua.insn_t )->bool: return idaapi.NN_jmp <= instruction.itype <= idaapi.NN_jmpshort

def is_skipped_data_junk(curr_instruction: ida_ua.insn_t, destination_address: idaapi.ea_t)->bool:
    addresses_delta: int = destination_address - curr_instruction.ea
    if 0 > addresses_delta or addresses_delta > 0x800: return False
    while curr_instruction.ea + curr_instruction.size <= destination_address:
        if ida_xref.get_next_cref_to(curr_instruction.ea, ida_xref.get_first_cref_to(curr_instruction.ea)) != idc.BADADDR: return False
        curr_instruction = idautils.DecodeInstruction(curr_instruction.ea + curr_instruction.size)
        if not curr_instruction:
            curr_addr = curr_instruction.ea
            while not curr_instruction and curr_instruction.ea + curr_instruction.size <= destination_address or curr_addr + 1 <= destination_address:
                curr_addr += 1
                curr_instruction = idautils.DecodeInstruction(curr_addr)
    return True

if __name__ == '__main__':
    main()