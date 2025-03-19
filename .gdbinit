# Load pwndbg
source ~/pwndbg/gdbinit.py

# Additional pwndbg customization
set disassembly-flavor intel
set debuginfod enabled on

# Disable the automatic update check
set environment PWNDBG_NO_AUTOUPDATE 1

# Common pwndbg settings
set context-sections code disasm stack regs

# Show a compact register display
set context-register-compact on 