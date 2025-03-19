"""
Radare2 integration for PwnAI.

This module provides a wrapper around r2pipe to interface with Radare2
for static binary analysis.
"""

import json
import re
import subprocess
import signal
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import threading

import r2pipe
from pwnai.utils.logger import setup_logger


class TimeoutError(Exception):
    """Exception raised when a command times out."""
    pass


class CommandExecutor:
    """Helper class to execute r2pipe commands with timeout."""
    
    def __init__(self, r2):
        self.r2 = r2
        self.result = None
        self.exception = None
    
    def execute(self, command):
        try:
            self.result = self.r2.cmd(command)
            # Some r2pipe commands return error messages as string results
            # rather than raising exceptions
            if self.result and isinstance(self.result, str):
                if "Cannot find" in self.result or "Invalid" in self.result:
                    self.exception = Exception(self.result)
                    self.result = None
        except Exception as e:
            self.exception = e


class Radare2:
    """
    Wrapper for Radare2 using r2pipe.
    
    This class provides methods to perform static analysis on binaries
    using Radare2's capabilities. It handles data parsing and provides
    a more Pythonic interface to common r2 operations.
    """
    
    def __init__(self, binary_path: Path):
        """
        Initialize the Radare2 wrapper.
        
        Args:
            binary_path: Path to the binary to analyze
        """
        self.binary_path = binary_path
        self.logger = setup_logger(name="pwnai.Radare2")
        
        # Initialize r2pipe
        try:
            self.r2 = r2pipe.open(str(binary_path))
            self.logger.debug(f"Initialized Radare2 for {binary_path}")
            
            # Run initial basic analysis with timeout
            self.cmd("aa", timeout=10)  # Analyze all
            self.logger.debug("Performed initial analysis")
        except Exception as e:
            self.logger.error(f"Failed to initialize Radare2: {str(e)}")
            raise

    def __del__(self):
        """Clean up r2pipe on object destruction."""
        if hasattr(self, "r2"):
            try:
                self.r2.quit()
                self.logger.debug("Closed r2pipe")
            except Exception as e:
                self.logger.warning(f"Error closing r2pipe: {str(e)}")

    def cmd(self, command: str, timeout: int = 5) -> str:
        """
        Execute a Radare2 command with timeout.
        
        Args:
            command: The radare2 command to execute
            timeout: Timeout in seconds
            
        Returns:
            The command output
            
        Raises:
            TimeoutError: If the command times out
        """
        # Skip potentially problematic commands
        if not command or not command.strip():
            return ""
            
        self.logger.debug(f"Executing command: {command}")
        
        # Some commands are known to be more complex, handle them with care
        if command.startswith("axt") or command.startswith("ax"):
            # These commands can be slow or hang if they're not applicable
            # Check if we're looking for a valid address
            match = re.search(r"@ ([^\s]+)", command)
            if match:
                ref_target = match.group(1)
                # Check if the target exists first
                check_cmd = f"is~{ref_target}"
                check_result = self._execute_command_with_timeout(check_cmd, 2)
                if not check_result or "Invalid" in check_result:
                    self.logger.debug(f"Skipping '{command}' - target {ref_target} not found")
                    return ""
        
        # Execute the command with timeout
        return self._execute_command_with_timeout(command, timeout)
    
    def _execute_command_with_timeout(self, command: str, timeout: int) -> str:
        """Internal method to execute a command with timeout handling."""
        # Create a thread to execute the command
        executor = CommandExecutor(self.r2)
        thread = threading.Thread(target=executor.execute, args=(command,))
        thread.daemon = True
        
        # Start the thread and wait for it to finish with timeout
        thread.start()
        thread.join(timeout)
        
        # Check if the thread is still alive (timeout)
        if thread.is_alive():
            self.logger.warning(f"Command '{command}' timed out after {timeout} seconds")
            # Let the thread continue running but we'll return an empty result
            return ""
        
        # Check if an exception occurred
        if executor.exception:
            if "Invalid" in str(executor.exception):
                self.logger.debug(f"Command '{command}' failed: {str(executor.exception)}")
            else:
                self.logger.error(f"Command '{command}' failed: {str(executor.exception)}")
            return ""
        
        return executor.result or ""
    
    def cmdj(self, command: str, timeout: int = 5) -> Optional[Any]:
        """
        Execute a Radare2 command that returns JSON and parse the result.
        
        Args:
            command: The radare2 command to execute
            timeout: Timeout in seconds
            
        Returns:
            Parsed JSON result or None if failed
        """
        result = self.cmd(command, timeout)
        
        if not result:
            return None
            
        try:
            return json.loads(result)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON result: {str(e)}")
            return None

    def get_binary_info(self) -> Dict[str, Any]:
        """
        Get basic information about the binary.
        
        Returns:
            Dictionary with binary metadata (arch, bits, OS, etc.)
        """
        info = self.cmdj("ij", timeout=5)
        if not info:
            self.logger.warning("Failed to get binary info")
            return {}
            
        # Extract security features with checksec-like info
        try:
            # Initialize security features as disabled by default
            security = {
                "pie": False,
                "canary": False,
                "nx": False,
                "relro": "no"
            }
            
            # First get better checksec output with more details
            checksec_output = self.cmd("iI~pic,canary,nx,NX,relro,RELRO,position", timeout=3)
            
            # Then parse each line carefully
            for line in checksec_output.splitlines():
                line = line.lower()
                # PIE/ASLR detection - look for multiple indicators
                if any(term in line for term in ["pic", "pie", "position independent", "aslr"]):
                    security["pie"] = any(term in line for term in ["true", "yes", "enabled", "position independent"])
                
                # Canary detection 
                if "canary" in line:
                    security["canary"] = any(term in line for term in ["true", "yes", "found", "enabled"])
                
                # NX detection - careful about negatives
                if "nx" in line:
                    if "nx disabled" in line or "nx unknown" in line:
                        security["nx"] = False
                    else:
                        security["nx"] = any(term in line for term in ["nx enabled", "true", "yes"])
                
                # RELRO detection
                if "relro" in line:
                    if "full relro" in line:
                        security["relro"] = "full"
                    elif "partial relro" in line:
                        security["relro"] = "partial"
                    else:
                        security["relro"] = "no"
            
            # Double-check with alternative methods
            
            # For PIE, check if base address is 0x400000 (no PIE) or different (PIE)
            base_addr_check = self.cmd("iM", timeout=2)
            if "0x400000" in base_addr_check and not security["pie"]:
                # Confirm no PIE for x86_64 ELF
                security["pie"] = False
            
            # Check canary by looking for stack_chk symbols
            canary_check = self.cmd("is~stack_chk", timeout=2)
            if canary_check.strip() and not security["canary"]:
                security["canary"] = True
            
            # Better NX check using the memory maps
            nx_check = self.cmd("i~^flags", timeout=2)
            if "executable" in nx_check.lower() and "stack" in nx_check.lower():
                # Executable stack implies no NX
                security["nx"] = False
            
            # Better RELRO check
            if security["relro"] == "no":
                relro_check = self.cmd("iS~.got.plt", timeout=2)
                if "READONLY" in relro_check:
                    security["relro"] = "full"
                elif ".got.plt" in relro_check:
                    security["relro"] = "partial"
            
            # Log and save the detected security features
            info["security"] = security
            self.logger.debug(f"Detected security features: {security}")
        except Exception as e:
            self.logger.warning(f"Failed to get security features: {str(e)}")
            # Make sure the dictionary exists even on error
            info["security"] = {
                "pie": False,
                "canary": False,
                "nx": False,
                "relro": "no"
            }
        
        return info
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """
        Get a list of all functions in the binary.
        
        Returns:
            List of dictionaries with function information
        """
        return self.cmdj("aflj", timeout=5) or []
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """
        Get a list of all imported functions.
        
        Returns:
            List of dictionaries with import information
        """
        return self.cmdj("iij", timeout=5) or []
    
    def get_strings(self) -> List[Dict[str, Any]]:
        """
        Get a list of all strings in the binary.
        
        Returns:
            List of dictionaries with string information
        """
        return self.cmdj("izj", timeout=5) or []
    
    def disassemble_function(self, function_name: str) -> List[Dict[str, Any]]:
        """
        Disassemble a function.
        
        Args:
            function_name: Name of the function to disassemble
            
        Returns:
            List of dictionaries with instruction information
        """
        # Make sure function exists
        result = self.cmdj(f"pdfj @ {function_name}", timeout=5)
        return result or []
    
    def disassemble_address(self, address: int, num_instructions: int = 20) -> List[Dict[str, Any]]:
        """
        Disassemble a number of instructions at the given address.
        
        Args:
            address: Address to start disassembling from
            num_instructions: Number of instructions to disassemble
            
        Returns:
            List of dictionaries with instruction information
        """
        # Check if address is a string or int
        addr_str = f"0x{address:x}" if isinstance(address, int) else address
        result = self.cmdj(f"pdj {num_instructions} @ {addr_str}", timeout=5)
        return result or []
    
    def find_vulnerable_functions(self) -> List[Dict[str, Any]]:
        """
        Find references to known vulnerable functions.
        
        Returns:
            List of dictionaries with vulnerability information
        """
        result = []
        
        # List of known vulnerable functions
        vulnerable_funcs = [
            "gets", "strcpy", "strcat", "sprintf", "scanf", "fscanf", "vsprintf",
            "system", "exec", "popen", "fork", "memcpy", "strncpy", "strncat", "snprintf"
        ]
        
        # Check imports for vulnerable functions
        imports = self.get_imports()
        import_names = set(imp.get("name", "") for imp in imports)
        
        # Build a map of imported vulnerable functions
        vuln_imports = {}
        for imp in imports:
            name = imp.get("name", "")
            if name in vulnerable_funcs:
                result.append({
                    "type": "imported_vulnerable_function",
                    "name": imp.get("name"),
                    "address": imp.get("vaddr"),
                })
                # Store the actual symbol name used in the binary
                sym_name = imp.get("plt_name") or f"sym.imp.{name}"
                vuln_imports[name] = sym_name
        
        # Check for xrefs to vulnerable functions - only for functions that exist in this binary
        for vf in vulnerable_funcs:
            if vf not in import_names:
                self.logger.debug(f"Skipping {vf} - not imported in this binary")
                continue
            
            # Get the correct symbol name from imports
            sym_name = vuln_imports.get(vf, f"sym.imp.{vf}")
            
            # First check if the symbol exists using the 'is' command
            symbol_check = self.cmd(f"is~{sym_name}", timeout=2)
            if not symbol_check:
                self.logger.debug(f"Symbol {sym_name} not found in binary")
                continue
                
            # Find cross-references to this function with a timeout
            xrefs_cmd = f"axt @ {sym_name}"
            xrefs = self.cmd(xrefs_cmd, timeout=5)  # Increase timeout to 5 seconds
            if not xrefs:  # Skip if empty or timed out
                self.logger.debug(f"No cross-references found for {sym_name}")
                continue
                
            for line in xrefs.splitlines():
                if line.strip():
                    # Extract the caller function and address
                    match = re.search(r"(0x[0-9a-f]+)\s+(\w+).*", line)
                    if match:
                        addr, ref_type = match.groups()
                        result.append({
                            "type": "vulnerable_function_call",
                            "function": vf,
                            "caller_address": addr,
                            "reference_type": ref_type,
                        })
        
        return result
    
    def analyze_binary(self) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of the binary.
        
        This method runs various analyses and returns a structured report.
        
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("Starting comprehensive binary analysis")
        
        # Initialize results dictionary with empty defaults
        results = {
            "binary_info": {},
            "functions": [],
            "imports": [],
            "strings": [],
            "vulnerable_functions": [],
            "entry_point": None,
            "main_disassembly": [],
            "entry_disassembly": []
        }
        
        # Run basic analysis commands first
        try:
            self.cmd("aaa", timeout=10)  # More comprehensive analysis
        except Exception as e:
            self.logger.warning(f"Basic analysis failed: {str(e)}")
            # Try fallback basic analysis
            self.cmd("aa", timeout=5)
            
        # Collect binary info
        try:
            results["binary_info"] = self.get_binary_info()
        except Exception as e:
            self.logger.warning(f"Failed to get binary info: {str(e)}")
            
        # Collect functions with timeout
        try:
            results["functions"] = self.get_functions()
        except Exception as e:
            self.logger.warning(f"Failed to get functions: {str(e)}")
            
        # Collect imports with timeout
        try:
            results["imports"] = self.get_imports()
        except Exception as e:
            self.logger.warning(f"Failed to get imports: {str(e)}")
            
        # Collect strings with timeout
        try:
            results["strings"] = self.get_strings()
        except Exception as e:
            self.logger.warning(f"Failed to get strings: {str(e)}")
            
        # Find vulnerable functions
        try:
            results["vulnerable_functions"] = self.find_vulnerable_functions()
        except Exception as e:
            self.logger.warning(f"Failed to find vulnerable functions: {str(e)}")
        
        # Try to identify entry point and main function
        try:
            entry_cmd = "iej"
            entry_result = self.cmd(entry_cmd, timeout=3)
            
            if entry_result:
                try:
                    entry_point = json.loads(entry_result)
                    if entry_point and isinstance(entry_point, list) and len(entry_point) > 0:
                        results["entry_point"] = entry_point[0].get("vaddr")
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse entry point information")
            
            # Get main function if available
            if results["functions"]:
                main_funcs = [f for f in results["functions"] if f.get("name") in ["main", "sym.main"]]
                if main_funcs:
                    try:
                        results["main_disassembly"] = self.disassemble_function("main")
                    except Exception as e:
                        self.logger.warning(f"Failed to disassemble main: {str(e)}")
                elif results["entry_point"]:
                    # If we can't find main, disassemble at entry point
                    try:
                        results["entry_disassembly"] = self.disassemble_address(results["entry_point"])
                    except Exception as e:
                        self.logger.warning(f"Failed to disassemble entry point: {str(e)}")
        except Exception as e:
            self.logger.warning(f"Failed to analyze entry point/main: {str(e)}")
                
        return results 