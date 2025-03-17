"""
Radare2 integration for PwnAI.

This module provides a wrapper around r2pipe to interface with Radare2
for static binary analysis.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import r2pipe
from pwnai.utils.logger import setup_logger


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
            binary_path: Path to the target binary
        """
        self.binary_path = binary_path
        self.logger = setup_logger(name="pwnai.Radare2")
        
        # Ensure Radare2 is installed
        try:
            subprocess.run(["r2", "-v"], check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.error("Radare2 is not installed or not in PATH")
            raise RuntimeError("Radare2 is required but not found")
        
        # Initialize r2pipe
        try:
            self.r2 = r2pipe.open(str(binary_path))
            self.logger.debug(f"Opened {binary_path} with r2pipe")
            
            # Initial analysis
            self.r2.cmd("aaa")  # Analyze all
            self.logger.debug("Performed initial analysis (aaa)")
        except Exception as e:
            self.logger.error(f"Failed to initialize r2pipe: {str(e)}")
            raise
    
    def __del__(self):
        """Clean up r2pipe on object destruction."""
        if hasattr(self, "r2"):
            self.r2.quit()
            self.logger.debug("Closed r2pipe")
    
    def get_binary_info(self) -> Dict[str, Any]:
        """
        Get basic information about the binary.
        
        Returns:
            Dictionary with binary metadata (arch, bits, OS, etc.)
        """
        info = self.r2.cmdj("ij")
        # Extract security features with checksec-like info
        try:
            checksec_output = self.r2.cmd("i~pic,canary,nx,relro")
            security = {}
            for line in checksec_output.splitlines():
                if "pic" in line.lower():
                    security["pie"] = "true" in line.lower()
                if "canary" in line.lower():
                    security["canary"] = "true" in line.lower()
                if "nx" in line.lower():
                    security["nx"] = "true" in line.lower()
                if "relro" in line.lower():
                    if "full" in line.lower():
                        security["relro"] = "full"
                    elif "partial" in line.lower():
                        security["relro"] = "partial"
                    else:
                        security["relro"] = "no"
            
            # Add the security info to the main info dict
            info["security"] = security
        except Exception as e:
            self.logger.warning(f"Failed to extract security features: {str(e)}")
        
        return info
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """
        Get a list of all functions in the binary.
        
        Returns:
            List of function dictionaries (name, address, size, etc.)
        """
        try:
            functions = self.r2.cmdj("aflj")
            if not functions:
                self.logger.warning("No functions found, trying deeper analysis...")
                self.r2.cmd("aaaa")  # More thorough analysis
                functions = self.r2.cmdj("aflj") or []
            return functions
        except Exception as e:
            self.logger.error(f"Failed to get functions: {str(e)}")
            return []
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """
        Get a list of imported functions.
        
        Returns:
            List of import dictionaries (name, address, type, etc.)
        """
        try:
            imports = self.r2.cmdj("iij")
            return imports if imports else []
        except Exception as e:
            self.logger.error(f"Failed to get imports: {str(e)}")
            return []
    
    def get_strings(self) -> List[Dict[str, Any]]:
        """
        Get a list of strings in the binary.
        
        Returns:
            List of string dictionaries (string, address, type, etc.)
        """
        try:
            strings = self.r2.cmdj("izj")
            return strings if strings else []
        except Exception as e:
            self.logger.error(f"Failed to get strings: {str(e)}")
            return []
    
    def disassemble_function(self, function_name: str) -> str:
        """
        Disassemble a function by name.
        
        Args:
            function_name: Name of the function to disassemble
            
        Returns:
            Disassembly text
        """
        return self.r2.cmd(f"pdf @ sym.{function_name}")
    
    def disassemble_address(self, address: Union[str, int]) -> str:
        """
        Disassemble at a specific address.
        
        Args:
            address: Memory address to disassemble at
            
        Returns:
            Disassembly text
        """
        return self.r2.cmd(f"pdf @ {address}")
    
    def find_vulnerable_functions(self) -> List[Dict[str, Any]]:
        """
        Look for potentially vulnerable function calls.
        
        This method searches for common dangerous functions like gets, strcpy,
        system, printf (for format string vulnerabilities), etc.
        
        Returns:
            List of dictionaries with vulnerable function info
        """
        vulnerable_funcs = [
            "gets", "strcpy", "strcat", "sprintf", "vsprintf",
            "scanf", "fscanf", "vscanf", "vfscanf", "printf",
            "system", "exec", "execl", "execlp", "execle",
            "execv", "execvp", "execvpe", "popen",
        ]
        
        result = []
        
        # Check imports for vulnerable functions
        imports = self.get_imports()
        for imp in imports:
            if any(vf == imp.get("name") for vf in vulnerable_funcs):
                result.append({
                    "type": "imported_vulnerable_function",
                    "name": imp.get("name"),
                    "address": imp.get("vaddr"),
                })
        
        # Check for xrefs to vulnerable functions
        for vf in vulnerable_funcs:
            # Find cross-references to this function
            xrefs_cmd = f"axt @ sym.imp.{vf}"
            xrefs = self.r2.cmd(xrefs_cmd)
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
        results = {
            "binary_info": self.get_binary_info(),
            "functions": self.get_functions(),
            "imports": self.get_imports(),
            "strings": self.get_strings(),
            "vulnerable_functions": self.find_vulnerable_functions(),
        }
        
        # Try to identify entry point and main function
        entry_point = self.r2.cmdj("iej")
        if entry_point:
            results["entry_point"] = entry_point[0].get("vaddr")
            
            # Disassemble main if we can find it
            main_funcs = [f for f in results["functions"] if f.get("name") in ["main", "sym.main"]]
            if main_funcs:
                results["main_disassembly"] = self.disassemble_function("main")
            else:
                # If we can't find main, disassemble at entry point
                results["entry_disassembly"] = self.disassemble_address(results["entry_point"])
        
        return results
    
    def execute_command(self, command: str) -> str:
        """
        Execute a raw Radare2 command.
        
        Args:
            command: Radare2 command to execute
            
        Returns:
            Command output as text
        """
        self.logger.debug(f"Executing r2 command: {command}")
        return self.r2.cmd(command)
    
    def execute_command_json(self, command: str) -> Any:
        """
        Execute a Radare2 command and parse JSON output.
        
        Args:
            command: Radare2 command to execute (should return JSON)
            
        Returns:
            Parsed JSON output
        """
        self.logger.debug(f"Executing r2 command (JSON): {command}")
        try:
            return self.r2.cmdj(command)
        except Exception as e:
            self.logger.error(f"Failed to execute command or parse JSON: {str(e)}")
            return None 