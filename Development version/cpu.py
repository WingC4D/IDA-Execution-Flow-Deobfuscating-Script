from flags import FlagsContext
from my_globals import __UINT__, __sBITS__, __16bit__, __32bit__, __64bit__,ida_allins, idautils, ida_ua

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
                self.registers[instruction.Op1.value] = instruction.Op2.value

            case ida_allins.NN_add:
                self.registers[instruction.Op1.value] += instruction.Op2.value
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

        self.flags._update(self.registers[instruction.Op1.value].value)
        return True

    def eval_cond_jump(self, instruction_type: int)->bool:
        match instruction_type:
            case ida_allins.NN_jo   : return self.flags.overflow
            case ida_allins.NN_js   : return self.flags.sign
            case ida_allins.NN_jl   : return self.flags.sign != self.flags.overflow
            case ida_allins.NN_jno  : return not self.flags.overflow
            case ida_allins.NN_jns  : return not self.flags.sign
            case ida_allins.NN_jcxz : return not self.reg_cx &  0xFFFF
            case ida_allins.NN_jecxz: return not self.reg_cx &  0xFFFFFFFF
            case ida_allins.NN_jrcxz: return not self.reg_cx &  0xFFFFFFFFFFFFFFFF
            case ida_allins.NN_jp   | ida_allins.NN_jpe : return self.flags.parity
            case ida_allins.NN_jbe  | ida_allins.NN_jna : return self.flags.carry or self.flags.zero
            case ida_allins.NN_jge  | ida_allins.NN_jnl : return self.flags.sign  == self.flags.overflow
            case ida_allins.NN_jle  | ida_allins.NN_jng : return self.flags.sign  != self.flags.overflow  or self.flags.zero
            case ida_allins.NN_jnz  | ida_allins.NN_jne : return not self.flags.zero
            case ida_allins.NN_jnp  | ida_allins.NN_jpo : return not self.flags.parity
            case ida_allins.NN_jg   | ida_allins.NN_jnle: return not self.flags.zero  and self.flags.sign == self.flags.overflow
            case ida_allins.NN_jnbe | ida_allins.NN_ja  : return not self.flags.carry and not self.flags.zero
            case ida_allins.NN_jz   | ida_allins.NN_je  | ida_allins.NN_jnge: return self.flags.zero
            case ida_allins.NN_jb   | ida_allins.NN_jc  | ida_allins.NN_jnae: return self.flags.carry
            case ida_allins.NN_jnb  | ida_allins.NN_jnc | ida_allins.NN_jae : return not self.flags.carry
            case default: return False
        
            