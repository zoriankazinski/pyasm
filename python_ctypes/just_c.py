import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'))
libc.printf(b"Hello World!\n")

