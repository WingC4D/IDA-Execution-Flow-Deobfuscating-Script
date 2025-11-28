from flags import FlagsContext
from my_globals import __UINT__, __sBITS__, __16bit__, __32bit__, __64bit__,ida_allins, idautils, ida_ua

class CpuContext:
    """CPU Context Class:\n
    - This class holds context to all registers & flags (currently of a 32bit processor)\n

    Data Members:\n
    1. registers:\n
    - type: dict\n
    - data: ctypes unsigned int in the cpu's bit size\n
    - indexing: idautils.procregs.REG.reg\n
    2. flags:\n
    - type: FlagsContext
    - details: see Flags context
    """

    def __init__(self):
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

    def update_regs_n_flags_imm(self, instruction: ida_ua.insn_t)->bool:
        if instruction.Op2.type == ida_ua.o_reg:
            right_oper_value: int = self.registers[instruction.Op2.reg].value
        else:
            right_oper_value = instruction.Op2.value
        org_reg_value  : int = self.registers[instruction.Op1.reg].value
        if instruction.itype == ida_allins.NN_mov:
            self.registers[instruction.Op1.reg].value = right_oper_value
            return True

        elif instruction in [ida_allins.NN_inc, ida_allins.NN_dec]:
            org_carry = self.flags.carry
            self.flags.reset()
            self.flags.carry = org_carry

        else:
            self.flags.reset()

        match instruction.itype:
            case ida_allins.NN_add:
                self.registers[instruction.Op1.reg].value += right_oper_value
                self.flags.set_carry_add(self.registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_add(self.registers[instruction.Op1.reg].value, org_reg_value,right_oper_value)

            case ida_allins.NN_and:
                self.registers[instruction.Op1.reg].value &= right_oper_value

            case ida_allins.NN_cmp:
                comp_result = __UINT__(self.registers[instruction.Op1.reg].value - right_oper_value)
                self.flags.set_carry_sub(comp_result.value, org_reg_value)
                self.flags.set_overflow_sub(comp_result.value, org_reg_value, right_oper_value)
                self.flags.update(comp_result.value)
                return True

            case ida_allins.NN_dec:
                self.registers[instruction.Op1.reg].value -= 1
                self.flags.set_overflow_sub(self.registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_inc:
                self.registers[instruction.Op1.reg].value += 1
                self.flags.set_overflow_add(self.registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_or:
                self.registers[instruction.Op1.reg].value |= right_oper_value

            case ida_allins.NN_sub:
                self.registers[instruction.Op1.reg].value -= right_oper_value
                self.flags.set_carry_sub(self.registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_sub(self.registers[instruction.Op1.reg].value, org_reg_value, right_oper_value)

            case ida_allins.NN_test:
                test_result = self.registers[instruction.Op1.reg].value & right_oper_value
                self.flags.update(test_result)
                return True

            case ida_allins.NN_xor:
                self.registers[instruction.Op1.reg].value ^= right_oper_value

            case default:
                print(f'Unhandled mnemonic of const {hex(instruction.itype)} @{instruction.ea:x}')

                return False

        self.flags.update(self.registers[instruction.Op1.reg].value)
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
            case ida_allins.NN_jg   | ida_allins.NN_jnle: return not self.flags.zero and self.flags.sign == self.flags.overflow
            case ida_allins.NN_jnbe | ida_allins.NN_ja  : return not self.flags.carry and not self.flags.zero
            case ida_allins.NN_jz   | ida_allins.NN_je  | ida_allins.NN_jnge: return self.flags.zero
            case ida_allins.NN_jb   | ida_allins.NN_jc  | ida_allins.NN_jnae: return self.flags.carry
            case ida_allins.NN_jnb  | ida_allins.NN_jnc | ida_allins.NN_jae : return not self.flags.carry
            case default: return False
