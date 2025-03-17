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
        
        # Ensure GDB is installed
        try:
            subprocess.run(["gdb", "--version"], check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.error("GDB is not installed or not in PATH")
            raise RuntimeError("GDB is required but not found")
        
        # Check for our GDB enhancements
        try:
            result = subprocess.run(
                ["gdb", "-q", "-nx", "-ex", "python print('GDB_ENHANCEMENT_CHECK')", "-ex", "quit"],
                check=False,
                capture_output=True,
                text=True,
            )
            has_enhancements = "GDB_ENHANCEMENT_CHECK" in result.stdout or "GDB_ENHANCEMENT_CHECK" in result.stderr
            if not has_enhancements:
                self.logger.warning("GDB enhancements not detected. Some functionality may be limited.")
        except Exception as e:
            self.logger.warning(f"Failed to check for GDB enhancements: {str(e)}")
        
        # Set architecture if provided, otherwise it will be auto-detected by Pwntools
        if arch:
            if arch == "x86":
                context.arch = "i386"
            elif arch == "x86_64":
                context.arch = "amd64"
            else:
                self.logger.warning(f"Unknown architecture: {arch}, using auto-detection")
        
        # Load the binary with Pwntools
        try:
            self.elf = ELF(str(binary_path))
            self.logger.debug(f"Loaded binary with Pwntools ELF: {binary_path}")
            
            # Set context based on the binary
            context.binary = self.elf
            self.logger.debug(f"Set pwntools context: {context.arch}")
        except Exception as e:
            self.logger.error(f"Failed to load binary with Pwntools: {str(e)}")
            raise
    
    def debug_binary(
        self,
        gdb_commands: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Debug the binary with specified GDB commands.
        
        Args:
            gdb_commands: List of GDB commands to execute
            env: Environment variables for the process
            stdin: Input to send to the process
            
        Returns:
            Tuple of (stdout, stderr) from the GDB session
        """
        gdb_commands = gdb_commands or []
        
        # Add quit command to ensure GDB exits
        if "quit" not in gdb_commands:
            gdb_commands.append("quit")
        
        # Create a temporary script with GDB commands
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".gdb") as f:
            for cmd in gdb_commands:
                f.write(f"{cmd}\n")
            gdb_script_path = f.name
        
        try:
            # Launch GDB with the script
            proc = process(["gdb", "-q", "-x", gdb_script_path, str(self.binary_path)])
            
            # Send stdin if provided - ensure it's encoded as bytes
            if stdin:
                # Convert string to bytes if it's not already
                stdin_bytes = stdin.encode('utf-8') if isinstance(stdin, str) else stdin
                proc.sendline(stdin_bytes)
            
            # Collect output with a timeout
            try:
                output = proc.recvall(timeout=30).decode("utf-8", errors="replace")
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
        
        try:
            # Create GDB process
            p = gdb.debug([str(self.binary_path)] + args, script, env=env, timeout=timeout)
            
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
        
        # Run with pattern as input
        gdb_commands = [
            "set pagination off",
            "set height 0",
            "set width 0",
            "run",  # Run until crash
            "info registers",  # Get all registers
            "bt",  # Get backtrace
            "quit",  # Ensure GDB exits
        ]
        
        # Debug with the pattern - pattern is already bytes from cyclic()
        stdout, stderr = self.debug_binary(gdb_commands=gdb_commands, stdin=pattern)
        
        if "Could not determine target architecture" in stdout:
            return None, "Architecture detection failed in GDB"
            
        # Check if we got a segfault
        if "SIGSEGV" not in stdout and "segmentation fault" not in stdout.lower():
            return None, f"No crash detected with cyclic pattern. Output: {stdout[:200]}"
            
        # Look for different register patterns based on architecture
        offset = None
        message = "Could not determine overflow offset from crash"
        
        # Try to find control of instruction pointer (EIP/RIP)
        ip_pattern = r"(e|r)ip\s*0x([0-9a-f]+)"
        matches = re.search(ip_pattern, stdout, re.IGNORECASE)
        
        if matches:
            reg_name, reg_value = matches.groups()
            try:
                reg_value_int = int(reg_value, 16)
                try:
                    # Try to find the offset in the cyclic pattern
                    offset = cyclic_find(reg_value_int)
                    if offset >= 0:
                        message = f"Found overflow offset at {offset} bytes (controls {reg_name})"
                        return offset, message
                except Exception as e:
                    self.logger.warning(f"Error finding cyclic offset: {str(e)}")
            except ValueError:
                self.logger.warning(f"Invalid register value: {reg_value}")
        
        # Try alternate approaches for different architectures
        # Check for x86 architecture with different register
        if context.arch == "i386":
            pc_pattern = r"eax\s*0x([0-9a-f]+)"
            matches = re.search(pc_pattern, stdout, re.IGNORECASE)
            if matches:
                reg_value = matches.group(1)
                try:
                    reg_value_int = int(reg_value, 16)
                    try:
                        offset = cyclic_find(reg_value_int)
                        if offset >= 0:
                            message = f"Found overflow offset at {offset} bytes (controls EAX)"
                            return offset, message
                    except Exception as e:
                        self.logger.warning(f"Error finding cyclic offset: {str(e)}")
                except ValueError:
                    self.logger.warning(f"Invalid register value: {reg_value}")
                    
        return offset, message
    
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
                        # Use the appropriate search method based on what's available
                        if hasattr(rop, "search"):
                            try:
                                # Try search without the multiple parameter first
                                found = rop.search(gadget)
                            except TypeError:
                                # If that fails, try with the multiple parameter
                                found = rop.search(gadget, multiple=True)
                        elif hasattr(rop, "find_gadget"):
                            found = rop.find_gadget([gadget])
                        else:
                            # Fallback to using raw search if available
                            raw_gadgets = self._find_raw_gadgets(gadget)
                            if raw_gadgets:
                                gadgets.extend(raw_gadgets)
                                continue
                        
                        # Handle found gadgets
                        if found:
                            if isinstance(found, list):
                                gadgets.extend(found)
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
        Check the security features of the binary.
        
        Returns:
            Dictionary of security features (NX, ASLR, Canary, etc.)
        """
        # Use pwntools checksec
        checksec_output = subprocess.run(
            ["checksec", "--file", str(self.binary_path)],
            capture_output=True,
            text=True,
        )
        
        result = {
            "nx": False,
            "canary": False,
            "pie": False,
            "relro": "No",
        }
        
        # Parse checksec output
        if "NX enabled" in checksec_output.stdout:
            result["nx"] = True
        if "Canary found" in checksec_output.stdout:
            result["canary"] = True
        if "PIE enabled" in checksec_output.stdout:
            result["pie"] = True
        if "Full RELRO" in checksec_output.stdout:
            result["relro"] = "Full"
        elif "Partial RELRO" in checksec_output.stdout:
            result["relro"] = "Partial"
        
        return result
    
    def get_libc_base(self) -> Optional[int]:
        """
        Get the base address of libc if loaded.
        
        Returns:
            Base address of libc or None if not found
        """
        gdb_commands = [
            "set pagination off",
            "run",  # Run to load libraries
            "info proc mappings",  # Get memory mappings
            "quit",
        ]
        
        # Run GDB commands
        stdout, _ = self.debug_binary(gdb_commands=gdb_commands)
        
        # Parse output for libc
        for line in stdout.splitlines():
            if "libc" in line and " r-xp " in line:  # Executable libc segment
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[0], 16)  # First column is start address
                    except ValueError:
                        pass
        
        return None
    
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
        
        try:
            # Create process
            p = process([str(self.binary_path)] + args)
            
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