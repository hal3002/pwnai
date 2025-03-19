"""
GDB integration for PwnAI.

This module provides utilities for interacting with GDB/Pwndbg
for dynamic binary analysis.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pwn import *  # Import all pwntools functionality
from pwnai.utils.logger import setup_logger


class GDBWrapper:
    """
    Wrapper for GDB/Pwndbg using Pwntools.
    
    This class provides methods for dynamic analysis of binaries using
    GDB with Pwndbg extensions.
    """
    
    def __init__(self, binary_path: Path, arch: Optional[str] = None):
        """
        Initialize the GDB wrapper.
        
        Args:
            binary_path: Path to the target binary
            arch: Target architecture (x86, x86_64)
                 If None, will be auto-detected
        """
        self.binary_path = binary_path
        self.logger = setup_logger(name="pwnai.GDBWrapper")
        
        # Validate binary path
        if not self.binary_path:
            self.logger.error("Binary path is None or empty")
            self.elf = None
            return
            
        if not os.path.exists(self.binary_path):
            self.logger.error(f"Binary not found: {self.binary_path}")
            self.elf = None
            return
            
        binary_path_str = str(self.binary_path)
        self.logger.debug(f"Initializing GDBWrapper for binary: {binary_path_str}")
        
        # Ensure GDB is installed
        try:
            subprocess.run(["gdb", "--version"], check=True, capture_output=True)
        except Exception as e:
            self.logger.error(f"GDB not found or not executable: {str(e)}")
            
        # Set up ELF object for the binary for pwntools integration
        try:
            self.elf = ELF(binary_path_str)
            
            # Set context arch based on binary if not specified
            if not arch:
                if self.elf.arch == "i386":
                    context.arch = "i386"
                elif self.elf.arch == "amd64":
                    context.arch = "amd64"
                elif "arm" in self.elf.arch:
                    context.arch = "arm"
                else:
                    context.arch = self.elf.arch
            else:
                if arch == "x86":
                    context.arch = "i386"
                elif arch == "x86_64":
                    context.arch = "amd64"
                else:
                    context.arch = arch
            
            self.logger.debug(f"Set architecture to {context.arch}")
            
        except Exception as e:
            self.logger.error(f"Failed to load binary as ELF: {str(e)}")
            self.elf = None
    
    def debug_binary(
        self,
        gdb_commands: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Run GDB commands against the binary.
        
        This runs GDB with a set of commands and returns the output.
        
        Args:
            gdb_commands: List of GDB commands to run
            env: Environment variables to set
            stdin: Input to send to the binary
            
        Returns:
            Tuple of (stdout, stderr)
        """
        # Validate binary path
        if not self.binary_path or not os.path.exists(self.binary_path):
            error_msg = f"Binary not found: {self.binary_path}"
            self.logger.error(error_msg)
            return "", error_msg
            
        binary_path_str = str(self.binary_path)
        self.logger.debug(f"Debugging binary: {binary_path_str}")
        
        # Default GDB commands if none provided
        gdb_commands = gdb_commands or ["help", "quit"]
        
        # Add safety measures to prevent hanging if 'run' is included
        has_run_cmd = any(cmd.strip().startswith("run") for cmd in gdb_commands)
        if has_run_cmd:
            # If running, add commands to kill after a timeout
            # and make sure stdin is sent properly
            # Find the index of the run command
            run_index = next((i for i, cmd in enumerate(gdb_commands) if cmd.strip().startswith("run")), -1)
            if run_index >= 0 and run_index < len(gdb_commands) - 1:
                # Add commands after run to ensure it terminates
                # Add these only if run is not the last command
                gdb_commands.insert(run_index + 1, "shell sleep 2")  # Give it 2 seconds to run
                gdb_commands.insert(run_index + 2, "kill")  # Then kill it
        
        # Add quit command to ensure GDB exits
        if "quit" not in gdb_commands:
            gdb_commands.append("quit")
        
        # Create a temporary script with GDB commands
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gdb") as f:
            for cmd in gdb_commands:
                f.write(f"{cmd}\n")
            gdb_script_path = f.name
        
        try:
            # Launch GDB with the script and a shortened timeout
            proc = process(["gdb", "-q", "-x", gdb_script_path, "-ex", "set confirm off", binary_path_str])
            
            # Send stdin if provided - ensure it's encoded as bytes
            if stdin:
                # Convert string to bytes if it's not already
                stdin_bytes = stdin.encode('utf-8') if isinstance(stdin, str) else stdin
                proc.sendline(stdin_bytes)
            
            # Collect output with a timeout
            try:
                output = proc.recvall(timeout=15).decode("utf-8", errors="replace")
            except Exception as e:
                self.logger.warning(f"Timeout or error while receiving GDB output: {str(e)}")
                proc.kill()
                return f"GDB process timed out or was killed. Last output: {proc.recvrepeat(0.1).decode('utf-8', errors='replace')}", str(e)
            
            # Parse for stdout/stderr
            return output, ""
        except Exception as e:
            self.logger.error(f"Error during GDB execution: {str(e)}")
            return "", str(e)
        finally:
            # Clean up the temporary script
            os.unlink(gdb_script_path)
    
    def run_pwntools_gdb(
        self,
        script: Optional[str] = None,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[Union[str, bytes]] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[process, str]:
        """
        Run the binary under GDB using Pwntools gdb.debug().
        
        Args:
            script: GDB script to run (string or path to file)
            args: Command line arguments for the binary
            env: Environment variables for the process
            stdin: Input to send to the process (string or bytes)
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (process object, GDB output)
        """
        args = args or []
        env = env or {}
        
        # Make sure binary path exists and is a string
        if not self.binary_path or not os.path.exists(self.binary_path):
            self.logger.error(f"Binary path does not exist: {self.binary_path}")
            return None, f"Binary not found: {self.binary_path}"
        
        binary_path_str = str(self.binary_path)
        self.logger.debug(f"Running GDB with binary: {binary_path_str}")
        
        try:
            # Create GDB process with properly converted binary path
            p = gdb.debug([binary_path_str] + args, script, env=env, timeout=timeout)
            
            # Send stdin if provided - ensure it's encoded as bytes
            if stdin:
                # Convert string to bytes if it's not already
                stdin_bytes = stdin.encode('utf-8') if isinstance(stdin, str) else stdin
                p.send(stdin_bytes)
                
            # Return the process so caller can interact further
            return p, "GDB started successfully"
        except Exception as e:
            self.logger.error(f"Error in pwntools GDB: {str(e)}")
            return None, str(e)
    
    def find_overflow_offset(self, max_length: int = 1024) -> Tuple[Optional[int], str]:
        """
        Find the offset at which we control EIP/RIP using a cyclic pattern.
        
        Args:
            max_length: Maximum length of the cyclic pattern
            
        Returns:
            Tuple of (offset if found, or None; log message)
        """
        # Create cyclic pattern
        pattern = cyclic(max_length)
        
        # Log architecture info for debugging
        self.logger.debug(f"Finding overflow offset with architecture: {context.arch}")
        
        # Make sure pattern is terminated with a newline
        if isinstance(pattern, bytes) and not pattern.endswith(b'\n'):
            pattern += b'\n'
        
        # Run with pattern as input
        gdb_commands = [
            "set pagination off",
            "set height 0",
            "set width 0",
            "break main",  # Break at main to ensure program is loaded
            "run",  # Run until the breakpoint
            "continue",  # Continue execution to allow input
            "bt",  # Get backtrace on crash
            "info registers",  # Get all registers
            "quit",  # Ensure GDB exits
        ]
        
        # Debug with the pattern - pattern is already bytes from cyclic()
        stdout, stderr = self.debug_binary(gdb_commands=gdb_commands, stdin=pattern)
        
        self.logger.debug(f"GDB output: {stdout[:500]}")
        
        if "Could not determine target architecture" in stdout:
            return None, "Architecture detection failed in GDB"
            
        # Check if we got a segfault
        if "SIGSEGV" not in stdout and "segmentation fault" not in stdout.lower():
            # Try an alternative approach without breaking at main
            gdb_commands = [
                "set pagination off",
                "set height 0",
                "set width 0",
                "run",  # Run directly
                "bt",  # Get backtrace on crash
                "info registers",  # Get all registers
                "quit",  # Ensure GDB exits
            ]
            
            # Try again with direct run
            stdout, stderr = self.debug_binary(gdb_commands=gdb_commands, stdin=pattern)
            self.logger.debug(f"Second attempt GDB output: {stdout[:500]}")
            
            if "SIGSEGV" not in stdout and "segmentation fault" not in stdout.lower():
                return None, f"No crash detected with cyclic pattern. Output: {stdout[:200]}"
            
        # Look for different register patterns based on architecture
        offset = None
        message = "Could not determine overflow offset from crash"
        
        # Debug register patterns in output
        register_matches = re.findall(r"([a-z0-9]+)\s+0x([0-9a-f]+)", stdout, re.IGNORECASE)
        registers_found = [f"{reg}=0x{val}" for reg, val in register_matches]
        self.logger.debug(f"Registers found: {registers_found}")
        
        # Try to find control of instruction pointer (EIP/RIP)
        ip_pattern = r"(e|r)ip\s*0x([0-9a-f]+)"
        matches = re.search(ip_pattern, stdout, re.IGNORECASE)
        
        if matches:
            reg_name, reg_value = matches.groups()
            try:
                reg_value_int = int(reg_value, 16)
                self.logger.debug(f"Found {reg_name.upper()} value: 0x{reg_value} ({reg_value_int})")
                
                # If the value is small (<256), it might be a direct array index
                if reg_value_int < 256:
                    self.logger.debug(f"Small register value might be direct offset: {reg_value_int}")
                    offset = reg_value_int
                    message = f"Found likely overflow offset at {offset} bytes (controls {reg_name.upper()})"
                    return offset, message
                
                try:
                    # Try to find the offset in the cyclic pattern
                    if context.arch == "i386":
                        # For 32-bit, use the value directly
                        offset = cyclic_find(reg_value_int & 0xffffffff)
                    else:
                        # For 64-bit, try different ways to pack the value
                        packed_val = p32(reg_value_int & 0xffffffff)
                        offset = cyclic_find(packed_val)
                        
                    if offset >= 0:
                        message = f"Found overflow offset at {offset} bytes (controls {reg_name.upper()})"
                        return offset, message
                    else:
                        # Try with different packing methods
                        for i in range(8):
                            try:
                                # Try each 4-byte aligned segment
                                val_slice = (reg_value_int >> (i*8)) & 0xffffffff
                                if val_slice == 0:
                                    continue
                                    
                                offset = cyclic_find(val_slice)
                                if offset >= 0:
                                    offset = offset - i
                                    message = f"Found overflow offset at {offset} bytes (controls {reg_name.upper()})"
                                    return offset, message
                            except Exception as e:
                                self.logger.debug(f"Error in alternative cyclic_find: {str(e)}")
                except Exception as e:
                    self.logger.warning(f"Error finding cyclic offset: {str(e)}")
            except ValueError:
                self.logger.warning(f"Invalid register value: {reg_value}")
        
        # Try alternate approaches for different architectures
        # Check for patterns in other important registers
        for reg_name in ["eax", "ebx", "ecx", "edx", "esp", "ebp"]:  # Include all important x86 registers
            reg_pattern = fr"{reg_name}\s*0x([0-9a-f]+)"
            matches = re.search(reg_pattern, stdout, re.IGNORECASE)
            if matches:
                reg_value = matches.group(1)
                try:
                    reg_value_int = int(reg_value, 16)
                    self.logger.debug(f"Found {reg_name.upper()} value: 0x{reg_value} ({reg_value_int})")
                    
                    # If the register contains a value that could be from our pattern
                    try:
                        # Try both direct value and packed value
                        for val in [reg_value_int, p32(reg_value_int & 0xffffffff)]:
                            offset = cyclic_find(val)
                            if offset >= 0:
                                message = f"Found overflow offset at {offset} bytes (controls {reg_name.upper()})"
                                return offset, message
                    except Exception as e:
                        self.logger.debug(f"Error in cyclic_find for {reg_name}: {str(e)}")
                except ValueError:
                    self.logger.debug(f"Invalid {reg_name} value: {reg_value}")
        
        # Check the stack for pattern values as a last resort
        try:
            # Find 4-byte values on the stack that match our pattern
            esp_match = re.search(r"esp\s*0x([0-9a-f]+)", stdout, re.IGNORECASE)
            if esp_match:
                esp_val = int(esp_match.group(1), 16)
                self.logger.debug(f"ESP value: 0x{esp_val:x}")
                
                # We would need to examine memory at ESP to find pattern values
                # This is a simplified approach - we look for 4-byte values in the output
                # that could be from our pattern
                for i in range(0, max_length - 3):
                    try:
                        val = cyclic(max_length)[i:i+4]
                        if val in stdout.encode('latin1', errors='ignore'):
                            offset = i
                            message = f"Found potential overflow offset at {offset} bytes (pattern on stack)"
                            return offset, message
                    except Exception as e:
                        pass
        except Exception as e:
            self.logger.debug(f"Error checking stack: {str(e)}")
        
        # If we still haven't found it, try some common buffer sizes
        common_offsets = [32, 64, 72, 76, 80, 84, 88, 96, 100, 104, 112, 128, 136, 140, 144]
        message = f"Could not determine overflow offset. Try common values: {common_offsets}"
        return None, message
    
    def find_gadgets(self, gadget_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find ROP gadgets in the binary and its linked libraries.
        
        Args:
            gadget_type: Type of gadget to find (e.g., "pop rdi", "ret")
                         If None, find all common gadgets
            
        Returns:
            List of gadget dictionaries (address, instruction, etc.)
        """
        try:
            # Initialize ROP object for the binary
            rop = ROP(self.elf)
            
            # Find gadgets
            gadgets = []
            
            if gadget_type:
                # Search for a specific type of gadget
                try:
                    # Try different methods of finding gadgets based on pwntools version
                    if hasattr(rop, "find_gadget"):
                        found = rop.find_gadget([gadget_type])
                        if found:
                            gadgets.append(found)
                    elif hasattr(rop, "search"):
                        # search method in newer versions doesn't accept 'multiple' parameter
                        found = rop.search(gadget_type)
                        if found:
                            gadgets.extend(found)
                except (AttributeError, TypeError) as e:
                    self.logger.warning(f"Error finding specific gadget: {str(e)}")
            else:
                # Define common gadgets based on architecture
                common_gadgets = []
                
                if context.arch == "i386":  # x86
                    common_gadgets = [
                        "pop ebp; ret", 
                        "pop eax; ret", 
                        "pop ebx; ret", 
                        "pop ecx; ret", 
                        "pop edx; ret", 
                        "int 0x80; ret"
                    ]
                elif context.arch == "amd64":  # x86_64
                    common_gadgets = [
                        "pop rdi; ret", 
                        "pop rsi; ret", 
                        "pop rdx; ret",
                        "pop rax; ret", 
                        "pop rbp; ret", 
                        "pop rsp; ret",
                        "syscall; ret"
                    ]
                elif context.arch == "arm" or context.arch == "aarch64":
                    common_gadgets = [
                        "pop {r0}; bx lr", 
                        "pop {r0, r1}; bx lr", 
                        "pop {r0-r3}; bx lr",
                        "blx sp", 
                        "mov lr, pc; bx r0"
                    ]
                
                # Always look for "ret" gadgets
                common_gadgets.append("ret")
                
                # Try to find each common gadget
                for gadget in common_gadgets:
                    try:
                        found = None  # Initialize found to None before attempting to search
                        # Use the appropriate search method based on what's available
                        if hasattr(rop, "search"):
                            try:
                                # Newer versions of pwntools use .search() without multiple parameter
                                found = rop.search(gadget)
                            except Exception as e:
                                # Log the error but don't try with the multiple parameter
                                self.logger.debug(f"Error using ROP.search for '{gadget}': {str(e)}")
                                # Fallback to raw gadget search
                                raw_gadgets = self._find_raw_gadgets(gadget)
                                if raw_gadgets:
                                    gadgets.extend(raw_gadgets)
                                    continue  # Skip the rest of this iteration
                        elif hasattr(rop, "find_gadget"):
                            found = rop.find_gadget([gadget])
                        else:
                            # Fallback to using raw search if available
                            raw_gadgets = self._find_raw_gadgets(gadget)
                            if raw_gadgets:
                                gadgets.extend(raw_gadgets)
                                continue  # Skip to next gadget
                        
                        # Only handle found gadgets if found is assigned and has a value
                        if found:
                            # Different pwntools versions return results in different formats
                            if isinstance(found, list):
                                gadgets.extend(found)
                            elif isinstance(found, dict):
                                # Handle dictionary result format (newer pwntools)
                                for addr in found.values():
                                    if addr:  # Check if the address is valid
                                        gadgets.append(addr)
                            else:
                                gadgets.append(found)
                    except Exception as e:
                        self.logger.warning(f"Error finding gadget '{gadget}': {str(e)}")
            
            # If no gadgets found using pwntools, try to use ROPgadget command-line tool as fallback
            if not gadgets:
                raw_gadgets = self._find_raw_gadgets(gadget_type)
                if raw_gadgets:
                    gadgets = raw_gadgets
            
            # Format the results
            result = []
            for gadget in gadgets:
                if isinstance(gadget, (int, str)):
                    # Handle when gadget is just an address or string
                    try:
                        addr = gadget if isinstance(gadget, int) else int(gadget, 16)
                        result.append({
                            "address": hex(addr),
                            "instruction": "unknown",
                            "binary": str(self.binary_path),
                        })
                    except (ValueError, TypeError):
                        # Skip invalid gadgets
                        continue
                else:
                    # Handle regular gadget object
                    try:
                        addr = gadget.address if hasattr(gadget, 'address') else gadget
                        if not isinstance(addr, int):
                            continue
                        result.append({
                            "address": hex(addr),
                            "instruction": str(gadget),
                            "binary": str(self.binary_path),
                        })
                    except (AttributeError, TypeError):
                        # Skip gadgets that don't fit expected format
                        continue
            
            return result
        except Exception as e:
            self.logger.error(f"Error finding gadgets: {str(e)}")
            return []
    
    def _find_raw_gadgets(self, pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find ROP gadgets using ROPgadget command-line tool as a fallback.
        
        Args:
            pattern: Pattern to search for
            
        Returns:
            List of gadget dictionaries
        """
        try:
            # Check if ROPgadget is available
            try:
                subprocess.run(["which", "ROPgadget"], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                # Try lowercase ropgadget if uppercase not found
                try:
                    subprocess.run(["which", "ropgadget"], capture_output=True, check=True)
                    # If lowercase works, use that
                    ropgadget_cmd = "ropgadget"
                except subprocess.CalledProcessError:
                    self.logger.warning("ROPgadget/ropgadget tool not found in PATH")
                    return []
            else:
                ropgadget_cmd = "ROPgadget"
                
            # Construct the ROPgadget command
            cmd = [ropgadget_cmd, "--binary", str(self.binary_path)]
            if pattern:
                # Ensure pattern string is properly formatted
                safe_pattern = pattern.replace(";", "\\;")  # Escape semicolons
                cmd.extend(["--only", safe_pattern])
            
            self.logger.debug(f"Running ROPgadget command: {' '.join(cmd)}")
                
            # Run the command with a timeout to prevent hanging
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            
            if result.returncode != 0:
                self.logger.warning(f"ROPgadget failed with code {result.returncode}: {result.stderr}")
                return []
                
            gadgets = []
            for line in result.stdout.splitlines():
                if "0x" in line:
                    # Parse the ROPgadget output format: "0xaddress : instruction"
                    parts = line.split(" : ")
                    if len(parts) >= 2:
                        addr_str = parts[0].strip()
                        instruction = parts[1].strip()
                        try:
                            addr = int(addr_str, 16)
                            gadgets.append({
                                "address": hex(addr),
                                "instruction": instruction,
                                "binary": str(self.binary_path),
                            })
                        except ValueError:
                            self.logger.debug(f"Failed to parse gadget address: {addr_str}")
            
            self.logger.info(f"Found {len(gadgets)} gadgets using ROPgadget")
            return gadgets
            
        except subprocess.TimeoutExpired:
            self.logger.warning("ROPgadget search timed out after 30 seconds")
            return []
        except Exception as e:
            self.logger.warning(f"Failed to use ROPgadget: {str(e)}")
            return []
    
    def dump_memory(self, address: int, size: int) -> bytes:
        """
        Dump memory from a specific address.
        
        Args:
            address: Memory address to dump from
            size: Number of bytes to dump
            
        Returns:
            Bytes of memory content
        """
        gdb_commands = [
            "set pagination off",
            "run",  # Run to start the program
            f"dump binary memory /tmp/memdump.bin {hex(address)} {hex(address + size)}",
            "quit",
        ]
        
        # Run GDB commands
        self.debug_binary(gdb_commands=gdb_commands)
        
        # Read the dumped memory
        try:
            with open("/tmp/memdump.bin", "rb") as f:
                memory = f.read()
            return memory
        except Exception as e:
            self.logger.error(f"Error reading memory dump: {str(e)}")
            return b""
    
    def check_security(self) -> Dict[str, bool]:
        """
        Check the security features of the binary using checksec.
        
        This uses Pwntools' checksec functionality rather than GDB commands
        for more accurate results.
        
        Returns:
            Dictionary with security features
        """
        self.logger.info("Checking binary security features")
        
        # Use pwntools checksec directly - more reliable than parsing GDB output
        try:
            # Use ELF built-in checks for security features
            security = {
                "pie": self.elf.pie,
                "canary": self.elf.canary,
                "nx": self.elf.nx,
                "relro": self.elf.relro
            }
            
            # Log all security features in detail
            self.logger.info(f"Security features from Pwntools: {security}")
            
            # Convert relro to boolean for consistency
            has_relro = security["relro"] != "No RELRO"
            security_bool = {
                "pie": bool(security["pie"]),
                "canary": bool(security["canary"]),
                "nx": bool(security["nx"]),
                "relro": has_relro,
                "full_relro": security["relro"] == "Full RELRO"
            }
            
            # Get detailed output for debug logs
            checksec_cmd = ["checksec", "--file", str(self.binary_path)]
            try:
                checksec_output = subprocess.run(
                    checksec_cmd, 
                    check=True, 
                    capture_output=True, 
                    text=True
                ).stdout
                self.logger.debug(f"checksec output: {checksec_output}")
            except Exception as e:
                self.logger.debug(f"Failed to run external checksec: {str(e)}")
            
            return security_bool
            
        except Exception as e:
            self.logger.error(f"Error checking security features: {str(e)}")
            # Provide default values as fallback
            return {
                "pie": False,
                "canary": False,
                "nx": False,
                "relro": False,
                "full_relro": False
            }
    
    def get_libc_base(self) -> Optional[int]:
        """
        Get the base address of libc if loaded.
        
        Returns:
            Base address of libc or None if not found
        """
        # Validate binary path
        if not self.binary_path or not os.path.exists(self.binary_path):
            self.logger.error(f"Binary path does not exist: {self.binary_path}")
            return None
            
        binary_path_str = str(self.binary_path)
        
        # First try using ldd to find if libc is linked
        libc_used = False
        libc_path = None
        try:
            # Check if we can find libc in the loaded libraries without running
            cmd = ["ldd", binary_path_str]
            self.logger.debug(f"Running ldd command: {cmd}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,  # Shorter timeout for ldd
                check=False
            )
            
            # Parse the ldd output for libc
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "libc.so" in line and "=>" in line:
                        parts = line.split("=>")
                        if len(parts) > 1:
                            path_part = parts[1].strip().split()[0]
                            if os.path.exists(path_part):
                                libc_path = path_part
                                libc_used = True
                                self.logger.debug(f"Found libc at: {libc_path}")
                                break
        except Exception as e:
            self.logger.warning(f"Error checking for libc with ldd: {str(e)}")
        
        # If we didn't find libc being used, no need to continue
        if not libc_used:
            self.logger.warning("No libc found or not dynamically linked")
            return None
            
        # Now use GDB to determine the actual base address at runtime
        try:
            # Prepare GDB commands to find libc base address
            gdb_commands = [
                "set pagination off",
                "set disassembly-flavor intel",
                "break main",  # Break at main to ensure libc is loaded
                "run",         # Run the program to hit the breakpoint
                "info proc mappings",  # Get memory mappings to find libc
                "quit"
            ]
            
            # Run GDB
            result = self.run_gdb_commands(gdb_commands)
            
            # Parse the output to find libc base address
            for line in result.splitlines():
                if libc_path and libc_path in line:
                    # Found the line with libc mapping
                    parts = line.strip().split()
                    # Memory mapping lines typically look like:
                    # start      end        size       offset     permissions  path
                    # 0x7ffff7dc6000 0x7ffff7fd0000 0x20a000 0 r-xp /lib/x86_64-linux-gnu/libc-2.31.so
                    if len(parts) >= 6 and parts[0].startswith("0x"):
                        libc_base = int(parts[0], 16)
                        self.logger.info(f"Found libc base address: {hex(libc_base)}")
                        return libc_base
                elif "libc" in line.lower() and ".so" in line:
                    # Found a line that mentions libc
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[0].startswith("0x"):
                        libc_base = int(parts[0], 16)
                        self.logger.info(f"Found libc base address: {hex(libc_base)}")
                        return libc_base
                        
            # If no specific libc path, look for any libc-like library
            for line in result.splitlines():
                if "libc" in line.lower() and ".so" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0].startswith("0x"):
                        libc_base = int(parts[0], 16)
                        self.logger.info(f"Found libc base address: {hex(libc_base)}")
                        return libc_base
            
            # If we haven't found it in mappings, try info sharedlibrary output
            # Prepare GDB commands to find libc base address using info sharedlibrary
            gdb_commands = [
                "set pagination off", 
                "set disassembly-flavor intel",
                "break main",
                "run",
                "info sharedlibrary",
                "quit"
            ]
            
            # Run GDB
            result = self.run_gdb_commands(gdb_commands)
            
            # Parse the output to find libc base address
            for line in result.splitlines():
                if "libc.so" in line:
                    # Info sharedlibrary format is typically:
                    # From        To          Syms Read   Shared Object Library
                    # 0x7ffff7dc6000  0x7ffff7fd0000  Yes         /lib/x86_64-linux-gnu/libc.so.6
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0].startswith("0x"):
                        libc_base = int(parts[0], 16)
                        self.logger.info(f"Found libc base address from sharedlibrary info: {hex(libc_base)}")
                        return libc_base
            
            # If ASLR is disabled and we have PIE disabled, libc might be at a fixed address
            # Let's just try to find a reasonable default value for testing
            if not self.check_aslr_enabled() and not self.elf.pie:
                # Try some common fixed addresses based on architecture
                if context.arch == "i386":  # 32-bit
                    default_base = 0xf7000000
                    self.logger.warning(f"Using default 32-bit libc base address: {hex(default_base)}")
                    return default_base
                elif context.arch == "amd64":  # 64-bit
                    default_base = 0x7ffff7000000
                    self.logger.warning(f"Using default 64-bit libc base address: {hex(default_base)}")
                    return default_base
            
            self.logger.warning("Could not determine libc base address")
            return None
            
        except Exception as e:
            self.logger.warning(f"Error determining libc base address: {str(e)}")
            return None
            
    def check_aslr_enabled(self) -> bool:
        """Check if ASLR is enabled on the system."""
        try:
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                value = int(f.read().strip())
            return value != 0
        except Exception:
            # Default to assuming ASLR is enabled if we can't check
            return True
    
    def try_exploit(self, payload: bytes, args: Optional[List[str]] = None) -> Tuple[bool, str]:
        """
        Try to run an exploit payload and check if it works.
        
        Args:
            payload: Exploit payload bytes
            args: Command line arguments for the binary
            
        Returns:
            Tuple of (success bool, output/error message)
        """
        args = args or []
        
        # Validate binary path
        if not self.binary_path or not os.path.exists(self.binary_path):
            error_msg = f"Binary not found: {self.binary_path}"
            self.logger.error(error_msg)
            return False, error_msg
            
        binary_path_str = str(self.binary_path)
        
        try:
            # Create process
            self.logger.debug(f"Running binary for exploit attempt: {binary_path_str}")
            p = process([binary_path_str] + args)
            
            # Send payload
            p.send(payload)
            
            # Try to check for success (e.g., shell prompt)
            try:
                p.sendline(b"id")
                response = p.recvline(timeout=2)
                
                if b"uid=" in response:
                    # We got a shell!
                    p.close()
                    return True, "Exploit successful! Shell obtained."
            except:
                pass
            
            # Generic check - try to interact for a bit
            try:
                output = p.recv(timeout=2)
                if output:
                    p.close()
                    return True, f"Binary still running after payload. Output: {output[:100]}"
            except:
                pass
            
            # Check if it crashed
            if p.poll() is not None:
                exit_code = p.poll()
                p.close()
                if exit_code < 0:
                    return False, f"Binary crashed with signal {-exit_code}"
                else:
                    return False, f"Binary exited with code {exit_code}"
            
            # If we got here, the binary is still running but no shell
            p.close()
            return False, "Binary still running but no shell detected"
        
        except Exception as e:
            return False, f"Error during exploit attempt: {str(e)}"
    
    def find_library_gadgets(self, library_name: str = "libc", pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find ROP gadgets in shared libraries like libc.
        
        Args:
            library_name: Name of the library (e.g., "libc")
            pattern: Pattern to search for (e.g., "pop rdi", "ret")
            
        Returns:
            List of gadget dictionaries with real addresses
        """
        try:
            # First get the library base address
            if library_name.lower() == "libc":
                library_base = self.get_libc_base()
                if not library_base:
                    self.logger.warning("Could not determine libc base address")
                    return []
                
                # Find the libc path
                libc_path = None
                if self.elf.libc:
                    libc_path = self.elf.libc.path
                else:
                    # Try to find libc path through ldd
                    try:
                        ldd_output = subprocess.check_output(["ldd", str(self.binary_path)], text=True)
                        for line in ldd_output.splitlines():
                            if "libc.so" in line:
                                # Extract the path from the ldd output
                                parts = line.split("=>")
                                if len(parts) > 1:
                                    libc_path = parts[1].strip().split()[0]
                                    break
                    except Exception as e:
                        self.logger.warning(f"Failed to find libc path through ldd: {str(e)}")
                
                if not libc_path or not os.path.exists(libc_path):
                    self.logger.warning(f"Could not find libc at {libc_path}")
                    return []
                
                # Now search for gadgets in the libc file
                cmd = ["ROPgadget", "--binary", libc_path]
                if pattern:
                    # Ensure pattern string is properly formatted
                    safe_pattern = pattern.replace(";", "\\;")  # Escape semicolons
                    cmd.extend(["--only", safe_pattern])
                
                self.logger.debug(f"Running ROPgadget command on libc: {' '.join(cmd)}")
                
                # Run the command with a timeout to prevent hanging
                result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
                
                if result.returncode != 0:
                    self.logger.warning(f"ROPgadget on libc failed: {result.stderr}")
                    return []
                
                # Parse the output to find gadgets
                gadgets = []
                for line in result.stdout.splitlines():
                    if "0x" in line:
                        # Parse the ROPgadget output format: "0xaddress : instruction"
                        parts = line.split(" : ")
                        if len(parts) >= 2:
                            offset_str = parts[0].strip()
                            instruction = parts[1].strip()
                            try:
                                # This is the offset within libc, add the base address for the real runtime address
                                offset = int(offset_str, 16)
                                real_addr = library_base + offset
                                gadgets.append({
                                    "address": hex(real_addr),
                                    "offset": offset_str,
                                    "instruction": instruction,
                                    "binary": libc_path,
                                })
                            except ValueError:
                                self.logger.debug(f"Failed to parse gadget offset: {offset_str}")
                
                self.logger.info(f"Found {len(gadgets)} gadgets in libc")
                return gadgets
            else:
                # For other libraries, similar approach can be implemented
                self.logger.warning(f"Finding gadgets in {library_name} not implemented yet")
                return []
                
        except Exception as e:
            self.logger.error(f"Error finding library gadgets: {str(e)}")
            return []
    
    def find_specific_gadget(self, pattern: str, library: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Find a specific gadget pattern in the binary or library.
        
        Args:
            pattern: Gadget pattern to search for (e.g., "pop rdi; ret")
            library: Optional library name to search in (e.g., "libc")
            
        Returns:
            Dictionary with gadget information if found, None otherwise
        """
        try:
            self.logger.info(f"Searching for gadget pattern: {pattern}")
            
            # Choose where to search based on library parameter
            if library:
                gadgets = self.find_library_gadgets(library, pattern)
            else:
                gadgets = self._find_raw_gadgets(pattern)
            
            # Return the first matching gadget if any found
            if gadgets:
                self.logger.info(f"Found gadget: {gadgets[0]['instruction']} at {gadgets[0]['address']}")
                return gadgets[0]
                
            # If no exact match found, try more flexible search
            if not pattern.endswith("ret") and "ret" not in pattern:
                # Try searching for the pattern followed by ret
                modified_pattern = f"{pattern}; ret"
                self.logger.info(f"Trying alternative pattern: {modified_pattern}")
                
                if library:
                    gadgets = self.find_library_gadgets(library, modified_pattern)
                else:
                    gadgets = self._find_raw_gadgets(modified_pattern)
                
                if gadgets:
                    self.logger.info(f"Found alternative gadget: {gadgets[0]['instruction']} at {gadgets[0]['address']}")
                    return gadgets[0]
            
            self.logger.warning(f"No gadget found matching pattern: {pattern}")
            return None
                
        except Exception as e:
            self.logger.error(f"Error finding specific gadget: {str(e)}")
            return None
    
    def run_gdb_commands(self, commands: List[str]) -> str:
        """
        Run a list of GDB commands and return the output.
        
        Args:
            commands: List of GDB commands to execute
            
        Returns:
            Output from GDB
        """
        if not commands:
            return ""
            
        # Create a temporary file to hold GDB commands
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for cmd in commands:
                f.write(cmd + '\n')
            script_path = f.name
            
        try:
            # Run GDB with the script
            gdb_cmd = ["gdb", "--batch", "-x", script_path, str(self.binary_path)]
            self.logger.debug(f"Running GDB command: {' '.join(gdb_cmd)}")
            
            result = subprocess.run(
                gdb_cmd,
                capture_output=True,
                text=True,
                timeout=15,  # Longer timeout for running GDB
                check=False
            )
            
            output = result.stdout + result.stderr
            return output
            
        except subprocess.TimeoutExpired:
            self.logger.warning("GDB command timed out")
            return ""
        except Exception as e:
            self.logger.warning(f"Error running GDB commands: {str(e)}")
            return ""
        finally:
            # Clean up the temporary script file
            try:
                os.unlink(script_path)
            except:
                pass 