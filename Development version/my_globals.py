import ctypes, enum
from idaapi import inf_is_16bit, inf_is_32bit_exactly,inf_is_64bit
# It's a skill issue lol.
__16bit__      : bool      = inf_is_16bit()
__32bit__      : bool      = inf_is_32bit_exactly()
__64bit__      : bool      = inf_is_64bit()
__JUMP_LIMIT__ : int       = 0x3
__OPER_COUNT__ : int       = 0x8

try:
    if __32bit__:
        __sBITS__    : str = '32'
        __iBITS__    : int = 32
        MSB_MASK     : int = 0x80000000
        __INT__      : object = ctypes.c_int32
        __UINT__     : object = ctypes.c_uint32
        MAX_REG_VALUE: int = 0xFFFFFFFF

    elif __64bit__:
        __sBITS__     : str = '64'
        __iBITS__     : int = 64
        MSB_MASK      : int = 0x8000000000000000
        __INT__       : object = ctypes.c_int64
        __UINT__      : object = ctypes.c_uint64
        MAX_REG_VALUE : int = 0xFFFFFFFFFFFFFFFF
        REG_BYTES_SIZE: int = 8

    elif __16bit__:
        __sBITS__    : str = '16'
        __iBITS__    : int = 16
        MSB_MASK     : int = 0x8000
        __INT__      : object = ctypes.c_uint16
        __UINT__     : object = ctypes.c_uint16
        MAX_REG_VALUE: int = 0xFFFF

    else: raise RuntimeError
except RuntimeError:
    print("couldn't identify the bit-ness of the file")
    exit(-1)
__HEAP_REF__ = MAX_REG_VALUE + 1

class SkippedDataState(enum.Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 1
    NOT_FINISHED_IS_CODE = 2

class DataTypes(enum.Enum):
    BYTE    = 0x1
    WORD    = 0x2
    DWORD   = 0x4
    QWORD   = 0x8
    POINTER = 0xC
    CHAR    = 0x10
    STRING  = 0x20
    TEB     = 0x100
    PEB     = 0x200
