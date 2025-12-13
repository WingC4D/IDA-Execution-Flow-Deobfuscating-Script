from ctypes import c_int16 ,c_int32, c_int64, c_uint16, c_uint32, c_uint64
from enum import Enum
from idaapi import inf_is_16bit, inf_is_32bit_exactly,inf_is_64bit
# It's a skill issue lol.
__16bit__      : bool      = inf_is_16bit()
__32bit__      : bool      = inf_is_32bit_exactly()
__64bit__      : bool      = inf_is_64bit()
__JUMP_LIMIT__ : int       = 0x5
__OPER_COUNT__ : int       = 0x8

try:
    if __32bit__:
        __sBITS__     : str    = '32'
        __iBITS__     : int    = 0x20
        MSB_MASK      : int    = 0x80000000
        MAX_REG_VALUE : int    = 0xFFFFFFFF
        REG_BYTES_SIZE: int    = 4
        __INT__       : object = c_int32
        __UINT__      : object = c_uint32

    elif __64bit__:
        __sBITS__     : str    = '64'
        __iBITS__     : int    = 0x40
        MSB_MASK      : int    = 0x8000000000000000
        MAX_REG_VALUE : int    = 0xFFFFFFFFFFFFFFFF
        REG_BYTES_SIZE: int    = 8
        __INT__       : object = c_int64
        __UINT__      : object = c_uint64


    elif __16bit__:
        __sBITS__     : str    = '16'
        __iBITS__     : int    = 0x10
        MSB_MASK      : int    = 0x8000
        MAX_REG_VALUE : int    = 0xFFFF
        REG_BYTES_SIZE: int    = 2
        __INT__       : object = c_int16
        __UINT__      : object = c_uint16

    else: raise RuntimeError

except RuntimeError: exit("couldn't identify the bit-ness of the file")

__HEAP_REF__: int = MAX_REG_VALUE + 1

class SkippedDataState(Enum):
    FINISHED_IS_NOT_JUNK = 0
    FINISHED_IS_JUNK     = 1
    NOT_FINISHED_IS_CODE = 2

class DataTypes(Enum):
    BYTE    = 0x1
    WORD    = 0x2
    DWORD   = 0x4
    QWORD   = 0x8
    POINTER = 0xC
    CHAR    = 0x10
    STRING  = 0x20
    TEB     = 0x100
    PEB     = 0x200
