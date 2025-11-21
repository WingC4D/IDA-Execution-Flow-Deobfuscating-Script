from my_globals import ida_ua
def exec_flow_shift_msg(instruction: ida_ua.insn_t)->None: 
    print(f'jumped to {instruction.Op1.addr:x} from {instruction.ea:x}')

def regs_msg(register_name: str, instruction: ida_ua.insn_t)->None: 
    return print(f'Found a reference to {register_name} @{instruction.ea:x}')

def cunt_msg(unhandled_flag: str)->None: 
    return print(f'This instruction uses a {unhandled_flag}, start handling it ya cunt.')

def unhandled_jump_msg (jump_name: str)->bool:
    print(f'[!] Hit an unhandled jump of type {jump_name} returning False')
    return False