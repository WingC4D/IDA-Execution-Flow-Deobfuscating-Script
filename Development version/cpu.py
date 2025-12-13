from flags import FlagsContext
from my_globals import __INT__, __UINT__, __sBITS__, __32bit__
import ida_allins, ida_ua
from idautils import procregs
class CpuContext:
    """CPU Context Class:\n
    - This class holds context to all registers & flags (currently of a 32bit processor)\n

    Data Members:\n
    1. registers:\n
    - type: dict\n
    - data: ctypes unsigned int in the cpu's bitness size\n
    - indexing: procregs.REG.reg\n
    2. flags:\n
    - type: FlagsContext
    - details: see Flags context
    """

    def __init__(self):
        try:
            if __32bit__:
                self.gen_registers: dict = {
                    procregs.eax.reg: __UINT__(0),
                    procregs.ebx.reg: __UINT__(0),
                    procregs.ecx.reg: __UINT__(0),
                    procregs.edx.reg: __UINT__(0),
                    procregs.edi.reg: __UINT__(0),
                    procregs.esi.reg: __UINT__(0),
                    procregs.ebp.reg: __UINT__(0x100000),
                    procregs.esp.reg: __UINT__(0x100000),
                    procregs.eip.reg: __UINT__(0)
                }

            else:
                raise NotImplementedError

        except NotImplementedError:
            exit(f"Currently only handles 32bit processors")
        self.seg_registers: dict = {
            procregs.cs.reg: __UINT__()

        }
        self.flags: FlagsContext = FlagsContext()

    @property
    def reg_ax(self): return self.gen_registers[procregs.eax.reg].value

    @property
    def reg_bx(self): return self.gen_registers[procregs.ebx.reg].value

    @property
    def reg_cx(self): return self.gen_registers[procregs.ecx.reg].value

    @property
    def reg_dx(self): return self.gen_registers[procregs.edx.reg].value

    @property
    def reg_di(self): return self.gen_registers[procregs.edi.reg].value

    @property
    def reg_si(self): return self.gen_registers[procregs.esi.reg].value

    @property
    def reg_bp(self): return self.gen_registers[procregs.ebp.reg].value

    @reg_bp.setter
    def reg_bp(self,  value: int)->None:
        self.reg_bp = value
        return
    @property
    def reg_sp(self)->int: return self.gen_registers[procregs.esp.reg].value

    @reg_sp.setter
    def reg_sp(self,  value: int)->None:
        self.gen_registers[procregs.esp.reg].value = value
        return

    @property
    def reg_ip(self): return self.gen_registers[procregs.eip.reg].value

    def __repr__(self)->str: return f"""CPU Context:
- Architecture: {__sBITS__}bit Intel || AMD\n\n- Integer Registers:\n\tReg_AX: {hex(self.reg_ax)}
\tReg_BX: {hex(self.reg_bx)}
\tReg_CX: {hex(self.reg_cx)}
\tReg_DX: {hex(self.reg_dx)}
\tReg_DI: {hex(self.reg_di)}
\tReg_SI: {hex(self.reg_si)}
\tReg_BP: {hex(self.reg_bp)}
\tReg_SP: {hex(self.reg_sp)}
\tReg_IP: {hex(self.reg_ip)}
    
- {self.flags}\n"""

    def update_regs_n_flags(self, instruction: ida_ua.insn_t, oper_value: int | str | None = 1)->bool:
        org_reg_value: int = self.gen_registers[instruction.Op1.reg].value
        if instruction.itype == ida_allins.NN_mov:
            if instruction.Op1.type == ida_ua.o_reg:
                self.gen_registers[instruction.Op1.reg].value = oper_value
            print(self)
            return True

        elif instruction in [ida_allins.NN_inc, ida_allins.NN_dec]:
            org_carry = self.flags.carry
            self.flags.reset()
            self.flags.carry = org_carry

        else:
            self.flags.reset()

        match instruction.itype:
            case ida_allins.NN_add:
                self.gen_registers[instruction.Op1.reg].value += oper_value
                self.flags.set_carry_add(self.gen_registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_add(self.gen_registers[instruction.Op1.reg].value, org_reg_value, oper_value)

            case ida_allins.NN_and:
                self.gen_registers[instruction.Op1.reg].value &= oper_value

            case ida_allins.NN_cmp:
                comp_result = __UINT__(self.gen_registers[instruction.Op1.reg].value - oper_value)
                self.flags.set_carry_sub(comp_result.value, org_reg_value)
                self.flags.set_overflow_sub(comp_result.value, org_reg_value, oper_value)
                self.flags.update(comp_result.value)
                return True

            case ida_allins.NN_dec:
                self.gen_registers[instruction.Op1.reg].value -= 1
                self.flags.set_overflow_sub(self.gen_registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_imul:
                self.flags.reset()
                left_value : int = __INT__(self.gen_registers[instruction.Op1.reg].value).value
                right_value: int = __INT__(oper_value).value
                print(f"[i] iMultiplying {left_value:x} by {right_value}")

                self.gen_registers[instruction.Op1.reg].value = left_value * right_value
                self.flags.set_overflow_imul(__INT__(org_reg_value).value, __INT__(oper_value).value)

            case ida_allins.NN_inc:
                self.gen_registers[instruction.Op1.reg].value += 1
                self.flags.set_overflow_add(self.gen_registers[instruction.Op1.reg].value, org_reg_value, 1)

            case ida_allins.NN_not:
                self.gen_registers[instruction.Op1.reg].value = ~self.gen_registers[instruction.Op1.reg].value

            case ida_allins.NN_or:
                self.gen_registers[instruction.Op1.reg].value |= oper_value

            case ida_allins.NN_sub:
                self.gen_registers[instruction.Op1.reg].value -= oper_value
                self.flags.set_carry_sub(self.gen_registers[instruction.Op1.reg].value, org_reg_value)
                self.flags.set_overflow_sub(self.gen_registers[instruction.Op1.reg].value, org_reg_value, oper_value)

            case ida_allins.NN_test:
                test_result = self.gen_registers[instruction.Op1.reg].value & oper_value
                self.flags.update(test_result)
                print(self)
                return True

            case ida_allins.NN_xor:
                self.gen_registers[instruction.Op1.reg].value ^= oper_value

            case default:
                print(f'Unhandled mnemonic of const {hex(instruction.itype)} @{instruction.ea:x}')

                return False

        self.flags.update(self.gen_registers[instruction.Op1.reg].value)
        print(self)
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
        return False

    def eval_cond_mov(self, instruction_type: int)->bool:
        match instruction_type:
            case ida_allins.NN_cmovbe: return self.flags.carry or self.flags.zero
            case ida_allins.NN_cmovg : return self.flags.sign == self.flags.overflow and not self.flags.zero
            case ida_allins.NN_cmovge: return self.flags.sign == self.flags.overflow
            case ida_allins.NN_cmovl : return self.flags.sign != self.flags.overflow
            case ida_allins.NN_cmovle: return self.flags.sign != self.flags.overflow or self.flags.zero
            case ida_allins.NN_cmovb : return self.flags.carry
            case ida_allins.NN_cmovo : return self.flags.overflow
            case ida_allins.NN_cmovp : return self.flags.parity
            case ida_allins.NN_cmovs : return self.flags.sign
            case ida_allins.NN_cmovz : return self.flags.zero
            case ida_allins.NN_cmovnz: return not self.flags.zero
            case ida_allins.NN_cmovns: return not self.flags.sign
            case ida_allins.NN_cmovnp: return not self.flags.parity
            case ida_allins.NN_cmovno: return not self.flags.overflow
            case ida_allins.NN_cmovnb: return not self.flags.carry
            case ida_allins.NN_cmova : return not self.flags.carry and not self.flags.zero
        return False
