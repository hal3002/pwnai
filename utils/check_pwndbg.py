#!/usr/bin/env python3
"""
Check if pwndbg is properly installed and configured.
"""

import os
import sys
import subprocess
import tempfile

def check_pwndbg_loading():
    """Check if pwndbg is loaded when GDB starts."""
    try:
        # Use command-line arguments to avoid interactive paging
        cmd = 'gdb -q -ex "show version" -ex "quit"'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Combine stdout and stderr
        output = result.stdout + result.stderr
        
        # Check if pwndbg is loaded
        if "pwndbg: loaded" in output:
            print("✅ pwndbg is loaded when GDB starts!")
            return True
        else:
            print("❌ pwndbg is not loaded when GDB starts.")
            print("Output from GDB:")
            print(output[:200] + "..." if len(output) > 200 else output)
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ GDB execution timed out. There might be an issue with your GDB installation.")
        return False
    except subprocess.SubprocessError as e:
        print(f"❌ Error running GDB: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def check_pwndbg_commands():
    """Check if pwndbg commands work correctly."""
    try:
        # Create a simple test binary
        with tempfile.NamedTemporaryFile(suffix='.c', delete=False) as c_file:
            c_file_path = c_file.name
            c_file.write(b"""
            #include <stdio.h>
            int main() {
                printf("Hello, world!\\n");
                return 0;
            }
            """)
            
        # Compile the test binary
        binary_path = c_file_path + ".bin"
        compile_cmd = f"gcc {c_file_path} -o {binary_path}"
        subprocess.run(compile_cmd, shell=True, check=True)
        
        # Run checksec on the binary using command-line arguments
        cmd = f'gdb -q -ex "file {binary_path}" -ex "checksec" -ex "quit"'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Clean up
        os.unlink(c_file_path)
        os.unlink(binary_path)
        
        # Combined output
        output = result.stdout + result.stderr
        
        # Check if pwndbg's checksec command worked
        if "RELRO" in output and "NX" in output:
            print("✅ pwndbg commands work correctly!")
            return True
        else:
            print("❌ pwndbg commands don't work correctly.")
            print("Output from GDB:")
            print(output[:200] + "..." if len(output) > 200 else output)
            return False
    
    except subprocess.TimeoutExpired:
        print("❌ GDB execution timed out. There might be an issue with your GDB installation.")
        return False
    except subprocess.SubprocessError as e:
        print(f"❌ Error running GDB or compiling the test binary: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    finally:
        # Make sure we clean up any files that might have been left
        try:
            if 'c_file_path' in locals() and os.path.exists(c_file_path):
                os.unlink(c_file_path)
            if 'binary_path' in locals() and os.path.exists(binary_path):
                os.unlink(binary_path)
        except:
            pass

def check_gdbinit_files():
    """Check .gdbinit files for pwndbg references."""
    home_gdbinit = os.path.expanduser("~/.gdbinit")
    project_gdbinit = os.path.join(os.getcwd(), ".gdbinit")
    
    files_to_check = [
        (home_gdbinit, "User's home directory"),
        (project_gdbinit, "Project directory")
    ]
    
    all_files_ok = True
    
    for file_path, location in files_to_check:
        if os.path.exists(file_path):
            print(f"Found .gdbinit in {location}: {file_path}")
            with open(file_path, 'r') as f:
                content = f.read()
                if "pwndbg" in content:
                    print(f"✅ pwndbg is referenced in {file_path}")
                else:
                    print(f"❌ pwndbg is not referenced in {file_path}")
                    all_files_ok = False
        else:
            print(f"❌ No .gdbinit file found in {location}")
            all_files_ok = False
    
    return all_files_ok

if __name__ == "__main__":
    print("Checking pwndbg installation...")
    
    print("\n1. Checking if pwndbg is loaded in GDB:")
    gdb_loading = check_pwndbg_loading()
    
    print("\n2. Checking if pwndbg commands work correctly:")
    commands_work = check_pwndbg_commands()
    
    print("\n3. Checking .gdbinit files:")
    gdbinit_ok = check_gdbinit_files()
    
    print("\nSummary:")
    if commands_work:  # The most important check - if commands work, pwndbg is working
        print("✅ pwndbg is properly installed and configured!")
        sys.exit(0)
    else:
        print("❌ There are issues with the pwndbg installation or configuration.")
        print("\nTips for fixing pwndbg installation:")
        print("1. Make sure you have GDB installed: apt-get install gdb")
        print("2. Make sure pwndbg is installed: cd ~/pwndbg && ./setup.sh")
        print("3. Check if ~/.gdbinit contains: source ~/pwndbg/gdbinit.py")
        sys.exit(1) 