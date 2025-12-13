from ida_ua import insn_t

def regs_msg(register_name: str, instruction:insn_t)->None:
    return print(f'Found a reference to {register_name} @{instruction.ea:x}')

def lazy_msg(unhandled_flag: str)->None: 
    return print(f'This instruction uses a {unhandled_flag}, start handling it ya lazy.')
