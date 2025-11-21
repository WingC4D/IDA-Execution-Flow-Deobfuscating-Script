import ctypes, enum, ida_allins, idaapi, idc, ida_auto, ida_bytes, ida_ua, ida_xref, ida_allins, idautils

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
