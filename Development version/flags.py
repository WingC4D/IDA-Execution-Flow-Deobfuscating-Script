from my_globals import MSB_MASK
class FlagsContext:
    def __init__(self)->None:
        self.zero           : bool = False
        self.parity         : bool = False
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
    
    def _update(self, result: int)->None:
        self.zero = result == 0
        self.set_parity(result)
        self.set_sign(result)