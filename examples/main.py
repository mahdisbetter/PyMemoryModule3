import pythonmemorymodule
import base64
import ctypes

with open('dll.dll', 'rb') as f:
    dll_bin = f.read()

dll = pythonmemorymodule.MemoryModule(data=dll_bin)
func = dll.get_proc_addr('AddNumbers')

func.argtypes = [ctypes.c_int, ctypes.c_int]  
func.restype = ctypes.c_int  

result = func(5, 10)
print(result)
