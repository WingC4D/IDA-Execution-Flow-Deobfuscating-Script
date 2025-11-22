import ida_allins, idaapi, idc, idautils, ida_allins, ida_bytes, ida_xref, ida_auto, ida_ua, ctypes, enum
# It's a skill issue lol.
__16bit__      : bool      = idaapi.inf_is_16bit()
__32bit__      : bool      = idaapi.inf_is_32bit_exactly()
__64bit__      : bool      = idaapi.inf_is_64bit()
__JUMP_LIMIT__ : int       = 0x4
__OPER_COUNT__ : int       = 0x8
__ARITHMETIC__ : list[int] = [ida_allins.NN_add, ida_allins.NN_sub, ida_allins.NN_inc, ida_allins.NN_dec, ida_allins.NN_mul, ida_allins.NN_div]
__COMPARATIVE__: list[int] = [ida_allins.NN_cmp, ida_allins.NN_test]

try:
    if __32bit__:
        __sBITS__    : str    = '32'
        __iBITS__    : int    =  32
        MSB_MASK     : int    =  0x80000000
        __UINT__     : object =  ctypes.c_uint32
        MAX_REG_VALUE: int    =  0xFFFFFFFF

    elif __64bit__:
        __sBITS__    : str    = '64'
        __iBITS__    : int    =  64
        MSB_MASK     : int    = 0x8000000000000000
        __UINT__     : object = ctypes.c_uint64
        MAX_REG_VALUE: int    = 0xFFFFFFFFFFFFFFFF

    elif __16bit__:
        __sBITS__    : str    = '16'
        __iBITS__    : int    =  16
        MSB_MASK     : int    = 0x8000
        __UINT__     : object = ctypes.c_uint16
        MAX_REG_VALUE: int    = 0xFFFF
    else:
        raise RuntimeError
except RuntimeError:
    print("couldn't identify the bit-ness of the file")
    exit(-1)

class SkippedDataState(enum.Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 1
    NOT_FINISHED_IS_CODE = 2

class FlagsContext:
    def __init__(self)->None:
        self.zero           : bool = False
        self.parity         : bool = False  # PF (bit 2): Parity flag - Set if the least-significant byte of the result contains an even number of bits set to 1; cleared otherwise.
        self.auxiliary_carry: bool = False
        self.overflow       : bool = False
        self.direction      : bool = False
        self.sign           : bool = False
        self.carry          : bool = False
        self.trap           : bool = False
        self.interrupt      : bool = False

    def __repr__(self)->str:
        return f"""Flag States:
        \tZF = {int(self.zero)}\tPF = {int(self.parity)}\tAF = {int(self.auxiliary_carry)}
        \tOF = {int(self.overflow)}\tSF = {int(self.sign)}\tDF = {int(self.direction)}
        \tCF = {int(self.carry)}\tTF= {int(self.trap)}\tIF = {int(self.interrupt)}"""
    
    @staticmethod
    def _check_sign(value)->bool                                     : return value & MSB_MASK != 0

    def set_sign(        self, result: int)->None                    : self.sign = result & MSB_MASK != 0
    def set_carry_add(   self, result: int, org_value_a: int,)->None : self.carry = result < org_value_a
    def set_carry_sub(   self, result: int, org_value_a: int,)->None : self.carry = result > org_value_a
    def set_overflow_add(self, result: int, org_value_a: int, value_b: int)->None:
        if self._check_sign(org_value_a) == self._check_sign(value_b): self.overflow = self._check_sign(value_b) != self._check_sign(result)
        else                                                         : self.overflow = False
        return
    def set_overflow_sub(self, result: int, org_value_a: int, value_b: int)->None:
        if self._check_sign(org_value_a) != self._check_sign(value_b): self.overflow = self._check_sign(value_b) == self._check_sign(result)
        else                                                         : self.overflow = False
        return

    def set_parity(self, result: int)->None:
        least_significant_byte: int = result & 0xFF
        bits_set_to_1         : int = 0
        curr_bit              : int = 1
        while curr_bit <= 0x80:
            if curr_bit & least_significant_byte: bits_set_to_1 += 1
            curr_bit <<= 1
        self.parity = bits_set_to_1 % 2 == 0
        return

    def reset(self)->None: self.carry, self.overflow, self.sign, self.zero, self.parity = False, False, False, False, False

    def update(self, result: int)->None:
        self.zero = result == 0
        self.set_parity(result)
        self.set_sign(result)

class CpuContext:
    def __init__(self):
        # Registers:
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
        # Flags:
        self.flags: FlagsContext = FlagsContext()

    @property
    def reg_ax(self): return self.registers[idautils.procregs.eax.reg].value
    @property
    def reg_bx(self): return self.registers[idautils.procregs.ebx.reg].value
    @property
    def reg_cx(self): return self.registers[idautils.procregs.ecx.reg].value
    @property
    def reg_dx(self): return self.registers[idautils.procregs.edx.reg].value
    @property
    def reg_di(self): return self.registers[idautils.procregs.edi.reg].value
    @property
    def reg_si(self): return self.registers[idautils.procregs.esi.reg].value
    @property
    def reg_bp(self): return self.registers[idautils.procregs.ebp.reg].value
    @property
    def reg_sp(self): return self.registers[idautils.procregs.esp.reg].value
    @property
    def reg_ip(self): return self.registers[idautils.procregs.eip.reg].value

    def __repr__(self)->str: return f"""
    CPU Context:
    - Architecture:
    \t{__sBITS__}bit Intel || AMD\n\n- Integer Registers:\n\tReg_AX: {hex(self.reg_ax)}
	\tReg_BX: {hex(self.reg_bx)}
	\tReg_CX: {hex(self.reg_cx)}
	\tReg_DX: {hex(self.reg_dx)}
	\tReg_DI: {hex(self.reg_di)}
	\tReg_SI: {hex(self.reg_si)}
	\tReg_BP: {hex(self.reg_bp)}
	\tReg_SP: {hex(self.reg_sp)}
	\tReg_IP: {hex(self.reg_ip)}
	
    - {self.flags}\n"""
            
    def update(self, instruction: ida_ua.insn_t,)->bool:
        org_reg_value: int = self.registers[instruction.Op1.value].value
        if instruction.itype in [ida_allins.NN_inc, ida_allins.NN_dec]:
            org_carry = self.flags.carry
            self.flags.reset()
            self.flags.carry = org_carry
        else:
            self.flags.reset()
        match instruction.itype:
            case ida_allins.NN_mov:
                self.registers[instruction.Op1.value].value = instruction.Op2.value

            case ida_allins.NN_add:
                self.registers[instruction.Op1.value].value += instruction.Op2.value
                self.flags.set_carry_add(org_reg_value, self.registers[instruction.Op1.value].value)
                self.flags.set_overflow_add(org_reg_value, instruction.Op2.value, self.registers[instruction.Op1.value].value)

            case ida_allins.NN_sub:
                self.registers[instruction.Op1.value].value -= instruction.Op2.value
                self.flags.set_carry_sub(org_reg_value, self.registers[instruction.Op1.value].value)
                self.flags.set_overflow_sub(org_reg_value, instruction.Op2.value, self.registers[instruction.Op1.value].value)

            case ida_allins.NN_dec:
                self.registers[instruction.Op1.value].value -= 1
                self.flags.set_overflow_sub(org_reg_value, 1, self.registers[instruction.Op1.value].value)

            case ida_allins.NN_inc:
                self.registers[instruction.Op1.value].value += 1
                self.flags.set_overflow_add(org_reg_value, 1, self.registers[instruction.Op1.value].value)

            case ida_allins.NN_cmp:
                operand_one_sign_status: bool = self.flags._check_sign(instruction.Op1.value)
                operand_two_sign_status: bool = self.flags._check_sign(instruction.Op2.value)
                comp_result            : int  = instruction.Op1.value - instruction.Op2.value
                if operand_one_sign_status  == operand_two_sign_status:
                    self.flags.zero = True
                elif operand_one_sign_status:
                    pass
                else:
                    pass   
                
            case ida_allins.NN_test:
                pass

            case default:
                print(f'Unhandled mnemonic of const {hex(instruction.itype)}')
                return False

        self.flags.update(self.registers[instruction.Op1.value].value)
        return True

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
            case ida_allins.NN_jg   | ida_allins.NN_jnle: return not self.flags.zero  and self.flags.sign == self.flags.overflow
            case ida_allins.NN_jnbe | ida_allins.NN_ja  : return not self.flags.carry and not self.flags.zero
            case ida_allins.NN_jz   | ida_allins.NN_je  | ida_allins.NN_jnge: return self.flags.zero
            case ida_allins.NN_jb   | ida_allins.NN_jc  | ida_allins.NN_jnae: return self.flags.carry
            case ida_allins.NN_jnb  | ida_allins.NN_jnc | ida_allins.NN_jae : return not self.flags.carry
            case default: return False
""" main()"""
def deobfuscate_false_uncond_jumps_and_calls(effective_address: idaapi.ea_t = idc.here(),
                                             context          : CpuContext  = CpuContext(), 
                                             jump_count       : int         = 0)->int:
    
    frame_start: idaapi.ea_t = effective_address
    while True:
        
        instruction: ida_ua.insn_t = idautils.DecodeInstruction(effective_address)
        context.registers[idautils.procregs.eip.reg].value = effective_address
        
        if not ida_bytes.is_code(ida_bytes.get_flags(effective_address)) or jump_count >= __JUMP_LIMIT__:
            if jump_count >= __JUMP_LIMIT__:
                print(f'[✓] Taken {__JUMP_LIMIT__} jumps, all finished.')
                break
            
            print(f'[✕] Not code @{effective_address:x}, breaking the loop.')
            
            break

        if instruction.itype == ida_allins.NN_call:
            print(f'[i] Called @{instruction.Op1.addr:x} from {instruction.ea:x}')
            if not handle_forward_movement(instruction):
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
            effective_address = instruction.Op1.addr
            frame_start       = instruction.Op1.addr
            jump_count       += 1
            
            continue

        if is_non_cond_jump(instruction):
            exec_flow_shift_msg(instruction)
            
            effective_address = instruction.Op1.addr
            frame_start       = instruction.Op1.addr
            jump_count       += 1
            
            continue

        if is_cond_jump(instruction):
            if context.eval_cond_jump(instruction.itype):
                if is_junk_condition(instruction, frame_start): 
                    print(f'[✓] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found to be junk!')
                
                else: 
                    print(f'[i] Conditional jump @{effective_address:x} of type: {hex(instruction.itype)} has been found NOT to be junk!')
                
                if not handle_forward_movement(instruction):
                    print('[✕] Handle Forward Movement Failed! breaking the loop')
                    break
                
                effective_address = instruction.Op1.addr
                frame_start       = instruction.Op1.addr
                jump_count       += 1
                
                continue

        if is_arithmetic(instruction) and instruction.Op2.type == ida_ua.o_imm:
            context.update(instruction)
        
        effective_address += instruction.size
    idc.jumpto(effective_address)
    return 0

def handle_forward_movement(instruction: ida_ua.insn_t)->bool:
    if not are_skipped_instructions_junk(instruction):
        print(f'[i] Data skipped from @{instruction.ea:x} to @{instruction.Op1.addr:x} has been found to be NOT junk!')
        
        return True
    
    print(f'[✓] Data skipped from @{instruction.ea:x} to @{instruction.Op1.addr:x} has been found to be junk!')
    
    if ida_bytes.del_items(instruction.ea + instruction.size, ida_bytes.DELIT_SIMPLE, instruction.Op1.addr - instruction.size - instruction.ea):
        print(f'[✓] Undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
        
        if not ida_bytes.is_code(ida_bytes.get_flags(instruction.Op1.addr)):
            print( f'[i] Byte @{instruction.Op1.addr:x} has been found to be undefined, attempting to create a new instruction...')
            new_len: int = ida_ua.create_insn(instruction.Op1.addr)
            
            if new_len:
                print(f'[✓] Created a new instruction @{instruction.Op1.addr:x}')
                
                return True
            
            else: 
                print(f'[✕] Failed to undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
        
        else: 
            print(f'[✓] @{instruction.Op1.addr:x} has been found to be a Head of type Code!')
            return True
    else:        
        print(f'[✕] Failed to undefined data from @{(instruction.ea + instruction.size):x} to {instruction.Op1.addr:x}')
    
    return False

def exec_flow_shift_msg(instruction: ida_ua.insn_t)->None: return print(f'jumped to {instruction.Op1.addr:x} from {instruction.ea:x}')
def regs_msg(register_name: str, instruction: ida_ua.insn_t)->None: return print(f'Found a reference to {register_name} @{instruction.ea:x}')
def lazy_msg(unhandled_flag: str)->None: return print(f'This instruction uses a {unhandled_flag}, start handling it ya lazy.')
def unhandled_jump_msg (jump_name: str)->bool:
    print(f'[!] Hit an unhandled jump of type {jump_name} returning False')
    return False

def contains_imm( operand_types: list[int])->bool: return ida_ua.o_imm  in operand_types
def contains_near(operand_types: list[int])->bool: return idaapi.o_near in operand_types
def contains_reg( operand_types: list[int])->bool: return ida_ua.o_reg  in operand_types

def get_operands_types(operand_objects: list[ida_ua.op_t] | None = None, instruction: ida_ua.insn_t | None = None)->list[int]:
    try:
        if not operand_objects:
            
            if not isinstance(instruction, ida_ua.insn_t):
                raise TypeError
            
            operand_objects = get_operand_objects(instruction)
        
        return [operand.type for operand in operand_objects]
    
    except TypeError:
        print("[x] get_operand_types::Error { No input was passed! }")
        
        return []
    
def get_operand_objects(instruction: ida_ua.insn_t)->list[ida_ua.op_t]:
    result: list[ida_ua.op_t] = []
    for i in range(__OPER_COUNT__):    
        if instruction[i].type == idaapi.o_void:
            break
        
        result.append(instruction[i])
    
    return result

def is_arithmetic(      instruction: ida_ua.insn_t)->bool: return instruction.itype in __ARITHMETIC__
def is_cond_jump(       instruction: ida_ua.insn_t)->bool: return ida_allins.NN_ja  <= instruction.itype <= ida_allins.NN_jz
def is_non_cond_jump(   instruction: ida_ua.insn_t)->bool: return ida_allins.NN_jmp <= instruction.itype <= ida_allins.NN_jmpshort
def is_junk_condition(  current_exec_instruction: ida_ua.insn_t, eval_start: idaapi.ea_t)->bool:
    previous_instruction     : ida_ua.insn_t = idautils.DecodeInstruction(idaapi.prev_head(current_exec_instruction.ea, 0))
    current_eval_instruction : ida_ua.insn_t = idautils.DecodeInstruction(eval_start)
    case_operand             : ida_ua.op_t   = previous_instruction.Op1
    
    if (previous_instruction.itype in __ARITHMETIC__  and case_operand.type == ida_ua.o_reg 
    or  previous_instruction.itype in __COMPARATIVE__ and previous_instruction.Op2.type  != idaapi.o_phrase):
        
        while current_eval_instruction.ea <= current_exec_instruction.ea:
            
            if (current_eval_instruction.Op2.type == idaapi.o_imm
            and current_eval_instruction.Op1.reg  == case_operand.reg
            and current_eval_instruction.itype    == ida_allins.NN_mov):
                return True
            
            current_eval_instruction = idautils.DecodeInstruction(current_eval_instruction.ea + current_eval_instruction.size)
    
    return False

def are_skipped_instructions_junk(instruction: ida_ua.insn_t)->bool:
    addresses_delta: int = helper_delta(instruction)
    if not addresses_delta:
        return False
    eval_instruction: ida_ua.insn_t = instruction
    next_addr       : idaapi.ea_t   = instruction.ea + instruction.size
    while next_addr <= instruction.Op1.addr:
        second_referer: idaapi.ea_t = ida_xref.get_next_cref_to(eval_instruction.ea, ida_xref.get_first_cref_to(eval_instruction.ea))
        
        if second_referer != idc.BADADDR and second_referer != idc.BADADDR != instruction.ea: 
            return False
        
        elif not ida_bytes.is_code(ida_bytes.get_flags(next_addr)):
            
            match are_skipped_unexplored_bytes_junk(next_addr, instruction.Op1.addr):
                
                case SkippedDataState.FINISHED_IS_NOT_JUNK        : return False
                case SkippedDataState.FINISHED_IS_JUNK            : return True
                case SkippedDataState.NOT_FINISHED_IS_CODE        : continue
        
        eval_instruction = idautils.DecodeInstruction(next_addr)
        next_addr        = eval_instruction.ea + eval_instruction.size
    
    return True

def helper_delta(instruction: ida_ua.insn_t)->int:
    addresses_delta: idaapi.ea_t = instruction.Op1.addr - instruction.size - instruction.ea
    
    if 0 > addresses_delta: 
        print(f'[i] Addresses Delta @{instruction.ea:x} has been found to be negative!')
    
    elif addresses_delta > 0x800: 
        print(f'[i] Addresses Delta @{instruction.ea:x} is shifting forward the execution flow more than 2048 bytes, this is not a junk execution flow shift!')
        return 0
    return addresses_delta

def are_skipped_unexplored_bytes_junk(effective_address: idaapi.ea_t, destination_address: idaapi.ea_t)->SkippedDataState:
    current_address: idaapi.ea_t = effective_address
    
    while current_address <= destination_address:
        
        first_xref: int    = ida_xref.get_first_cref_to(effective_address)
        effective_address += 1
        
        if not first_xref:
            print(f'[i] Skipped byte @{effective_address:x} is not referenced by ANY code')
            continue
        
        if ida_xref.get_next_cref_to(effective_address, first_xref) != idc.BADADDR:
            return SkippedDataState.FINISHED_IS_NOT_JUNK
        
        elif ida_bytes.is_code(ida_bytes.get_flags(effective_address)): 
            return SkippedDataState.NOT_FINISHED_IS_CODE
    
    return SkippedDataState.FINISHED_IS_JUNK

if __name__ == '__main__':

    idaapi.msg_clear()
    print('IDA\'s Auto Analysis State Check Result is:', ida_auto.is_auto_enabled())
    print(f'main has finished with code: {hex(deobfuscate_false_uncond_jumps_and_calls())}')