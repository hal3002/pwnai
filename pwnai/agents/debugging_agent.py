"""
Debugging Agent for PwnAI.

This agent is responsible for performing dynamic analysis on binaries
to verify vulnerabilities and gather exploitation information.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pwnai.agents.base_agent import BaseAgent
from pwnai.tools.gdb import GDBWrapper
from pwnai.utils.llm_service import LLMService


class DebuggingAgent(BaseAgent):
    """
    Agent for debugging and dynamic analysis of binaries.
    
    This agent uses GDB/Pwndbg to perform dynamic analysis, verify
    vulnerabilities, and gather information needed for exploitation.
    """
    
    def __init__(
        self,
        state: Dict[str, Any],
        binary_path: Path,
        output_dir: Path,
        llm_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the Debugging Agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM
        """
        super().__init__(state, binary_path, output_dir, llm_config)
        
        # Get architecture from state if available
        arch = None
        if "architecture" in self.state:
            arch_info = self.state["architecture"]
            if arch_info.get("arch") == "x86" and arch_info.get("bits") == 64:
                arch = "x86_64"
            elif arch_info.get("arch") == "x86" and arch_info.get("bits") == 32:
                arch = "x86"
            elif arch_info.get("arch") == "arm" and arch_info.get("bits") == 64:
                arch = "arm64"
            elif arch_info.get("arch") == "arm":
                arch = "arm"
        
        # Initialize GDB wrapper
        self.gdb = GDBWrapper(binary_path, arch=arch)
        
        # Initialize LLM service
        llm_system_prompt = """
        You are a binary exploitation and debugging expert. You have deep knowledge of 
        assembly, memory layouts, debugging techniques, and exploitation.
        
        You are given information from GDB debugging sessions, including crash reports,
        register values, memory dumps, and other dynamic analysis data.
        
        Your task is to analyze this debugging information and help identify:
        
        1. How to trigger vulnerabilities
        2. Specific offsets or values needed for exploitation (like buffer overflow offsets)
        3. Memory layout information useful for exploitation
        4. How to bypass any security mechanisms
        
        Be precise in your analysis and provide specific, actionable information that can
        be used to develop an exploit. Include exact values, addresses, and offsets when possible.
        """
        
        self.llm = LLMService(
            system_prompt=llm_system_prompt,
            **(llm_config or {})
        )
    
    def run(self, tasks: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run dynamic analysis on the binary.
        
        Args:
            tasks: List of specific debugging tasks to perform
                   If None, will determine tasks based on state
        
        Returns:
            Updated state dictionary with findings
        """
        self.logger.info("Starting dynamic analysis of binary")
        
        # Determine tasks to run
        if not tasks:
            tasks = self._determine_tasks()
        
        # Initialize results
        results = {}
        
        # Run security checks
        security_features = self.gdb.check_security()
        self.logger.info(f"Security features: {security_features}")
        results["security_features"] = security_features
        
        # Process each task
        for task in tasks:
            self.logger.info(f"Running debugging task: {task}")
            
            if task == "find_overflow_offset":
                offset, message = self.gdb.find_overflow_offset()
                self.logger.info(message)
                results["overflow_offset"] = offset
                results["overflow_message"] = message
            
            elif task == "find_format_string_leak":
                leaked_addresses = self._find_format_string_leak()
                results["leaked_addresses"] = leaked_addresses
            
            elif task == "find_gadgets":
                gadgets = self.gdb.find_gadgets()
                self.logger.info(f"Found {len(gadgets)} potential ROP gadgets")
                results["rop_gadgets"] = gadgets
            
            elif task == "get_libc_base":
                libc_base = self.gdb.get_libc_base()
                self.logger.info(f"Libc base address: {hex(libc_base) if libc_base else 'Not found'}")
                results["libc_base"] = libc_base
            
            elif task == "analyze_crash":
                crash_analysis = self._analyze_crash()
                results["crash_analysis"] = crash_analysis
        
        # Save results to disk
        debug_results_path = self.output_dir / "debug_results.json"
        with open(debug_results_path, "w") as f:
            # Convert non-serializable types (like addresses) to strings
            serializable_results = self._make_serializable(results)
            json.dump(serializable_results, f, indent=2)
        
        self.logger.info(f"Saved debugging results to {debug_results_path}")
        
        # Get analysis from LLM
        debug_analysis = self._analyze_debug_results(results)
        debug_analysis_path = self.output_dir / "debug_analysis.txt"
        with open(debug_analysis_path, "w") as f:
            f.write(debug_analysis)
        
        self.logger.info(f"Saved debugging analysis to {debug_analysis_path}")
        
        # Update state with findings
        results["debug_analysis"] = debug_analysis
        self.update_state({"debug_results": results})
        
        # Log summary of findings
        if "overflow_offset" in results and results["overflow_offset"] is not None:
            self.log_result(f"Found buffer overflow offset: {results['overflow_offset']} bytes")
        if "leaked_addresses" in results and results["leaked_addresses"]:
            self.log_result(f"Found {len(results['leaked_addresses'])} leaked addresses")
        if "libc_base" in results and results["libc_base"]:
            self.log_result(f"Found libc base address: {hex(results['libc_base'])}")
        
        return self.state
    
    def _determine_tasks(self) -> List[str]:
        """
        Determine which debugging tasks to run based on state.
        
        Returns:
            List of task names
        """
        tasks = []
        
        # If vulnerabilities were identified by Reversing Agent
        if "vulnerabilities" in self.state:
            for vuln in self.state.get("vulnerabilities", []):
                vuln_type = vuln.get("type", "").lower()
                
                if "buffer overflow" in vuln_type or "stack overflow" in vuln_type:
                    tasks.append("find_overflow_offset")
                    tasks.append("find_gadgets")
                
                if "format string" in vuln_type:
                    tasks.append("find_format_string_leak")
                
                if any(x in vuln_type for x in ["rop", "return oriented", "aslr bypass"]):
                    tasks.append("get_libc_base")
                    tasks.append("find_gadgets")
        
        # If no specific vulnerabilities identified, run general tasks
        if not tasks:
            self.logger.info("No specific vulnerabilities identified, running general tasks")
            tasks = ["find_overflow_offset", "find_gadgets", "analyze_crash", "get_libc_base"]
        
        # Always add analyze_crash if not already included
        if "analyze_crash" not in tasks:
            tasks.append("analyze_crash")
        
        return tasks
    
    def _find_format_string_leak(self) -> List[Dict[str, Any]]:
        """
        Try to leak memory using format strings.
        
        Returns:
            List of leaked addresses and their context
        """
        # Try different format string payloads to leak memory
        payloads = [
            b"%p %p %p %p %p %p %p %p",  # Basic pointer leak
            b"%1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p",  # Positional leak
            b"%s%s%s%s%s%s%s%s",  # String leak (dangerous!)
        ]
        
        leaked_addresses = []
        
        for payload in payloads:
            try:
                # Create GDB script
                gdb_commands = [
                    "set pagination off",
                    "set height 0",
                    "set width 0",
                    "b main",  # Break at main
                    "run",  # Start execution
                    "continue",  # Continue to input
                ]
                
                # Run with payload
                p, gdb_output = self.gdb.run_pwntools_gdb(
                    script="\n".join(gdb_commands),
                    stdin=payload,
                    timeout=10  # Set a timeout to avoid hanging
                )
                
                if p:
                    # Collect output (which might contain leaked addresses)
                    try:
                        output = p.recvall(timeout=10)  # Set a reasonable timeout
                        output_str = output.decode('utf-8', errors='replace')
                        
                        # Look for hexadecimal addresses in the output
                        import re
                        address_matches = re.findall(r'0x[0-9a-f]{6,16}', output_str)
                        
                        for addr in address_matches:
                            leaked_addresses.append({
                                "address": addr,
                                "payload": payload.decode('utf-8', errors='replace'),
                                "context": "Format string leak",
                            })
                        
                        self.logger.info(f"Found {len(address_matches)} addresses from payload {payload}")
                    
                    except Exception as e:
                        self.logger.warning(f"Error collecting output: {str(e)}")
                    
                    finally:
                        # Ensure the process is closed
                        if p and p.poll() is None:
                            p.close()
            
            except Exception as e:
                self.logger.warning(f"Error testing format string payload {payload}: {str(e)}")
        
        return leaked_addresses
    
    def _analyze_crash(self) -> Dict[str, Any]:
        """
        Run the binary until it crashes and analyze the crash.
        
        Returns:
            Dictionary with crash analysis information
        """
        # Create a cyclic pattern to potentially trigger a crash
        from pwn import cyclic
        pattern = cyclic(1024)
        
        # Set up GDB commands
        gdb_commands = [
            "set pagination off",
            "set height 0",
            "set width 0",
            "run",  # Run until crash or completion
            "bt",  # Backtrace on crash
            "info registers",  # Register state
            "quit",  # Make sure GDB exits
        ]
        
        # Run the binary
        try:
            self.logger.debug("Running binary with cyclic pattern to analyze crash")
            stdout, stderr = self.gdb.debug_binary(
                gdb_commands=gdb_commands,
                stdin=pattern.decode('latin1')
            )
            
            # Parse the output for crash information
            result = {
                "crashed": "SIGSEGV" in stdout or "SIGABRT" in stdout,
                "output": stdout[:2000],  # Limit output size
                "registers": {},
                "backtrace": [],
            }
            
            if not result["crashed"]:
                self.logger.info("Binary did not crash with cyclic pattern input")
                return result
            
            # Extract register values
            import re
            reg_pattern = r'([a-z0-9]+)\s+0x([0-9a-f]+)'
            for match in re.finditer(reg_pattern, stdout):
                reg_name, reg_value = match.groups()
                try:
                    result["registers"][reg_name] = int(reg_value, 16)
                except ValueError:
                    self.logger.warning(f"Invalid register value: {reg_value}")
            
            # Extract backtrace
            bt_lines = []
            bt_section = False
            for line in stdout.splitlines():
                if line.startswith("#"):
                    bt_section = True
                    bt_lines.append(line)
                elif bt_section and not line.strip():
                    bt_section = False
            
            result["backtrace"] = bt_lines
            
            # Check if we control EIP/RIP
            for reg in ["eip", "rip", "pc"]:  # Add "pc" for ARM
                if reg in result["registers"]:
                    try:
                        # Check if the register value is part of our pattern
                        from pwn import cyclic_find
                        reg_value = result["registers"][reg]
                        offset = cyclic_find(reg_value)
                        if offset >= 0:
                            result["controlled_pc"] = True
                            result["pc_offset"] = offset
                            break
                        
                        # Try with packed value (for 64-bit)
                        from pwn import p32
                        offset = cyclic_find(p32(reg_value & 0xffffffff))
                        if offset >= 0:
                            result["controlled_pc"] = True
                            result["pc_offset"] = offset
                            break
                    
                    except Exception as e:
                        self.logger.warning(f"Error checking PC control: {str(e)}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during crash analysis: {str(e)}")
            return {
                "crashed": False,
                "error": str(e),
                "output": "Error during crash analysis",
                "registers": {},
                "backtrace": [],
            }
    
    def _analyze_debug_results(self, results: Dict[str, Any]) -> str:
        """
        Use LLM to analyze the debugging results.
        
        Args:
            results: The debugging results
            
        Returns:
            Analysis as text
        """
        # Create a prompt with the most relevant information
        prompt = """
        Please analyze the following debugging information and provide insights for exploitation.
        
        ## SECURITY FEATURES
        {security_features}
        
        ## BUFFER OVERFLOW
        {overflow_info}
        
        ## FORMAT STRING LEAKS
        {format_leaks}
        
        ## CRASH ANALYSIS
        {crash_analysis}
        
        ## LIBC BASE
        {libc_base}
        
        ## ROP GADGETS
        {rop_gadgets}
        
        Based on this information, please provide:
        1. Confirmation of the vulnerabilities found
        2. Specific exploitation details (offsets, addresses, etc.)
        3. A recommended exploitation strategy
        4. Any additional information needed for successful exploitation
        
        Be specific and provide exact values where available.
        """
        
        # Format security features
        security_features = results.get("security_features", {})
        security_text = "\n".join([f"- {k.upper()}: {v}" for k, v in security_features.items()])
        
        # Format overflow info
        overflow_text = "No buffer overflow detected."
        if "overflow_offset" in results and results["overflow_offset"] is not None:
            overflow_text = f"Buffer overflow detected with offset: {results['overflow_offset']} bytes\n"
            overflow_text += f"Message: {results.get('overflow_message', '')}"
        
        # Format format string leaks
        format_leaks = results.get("leaked_addresses", [])
        if format_leaks:
            format_text = f"Found {len(format_leaks)} leaked addresses:\n"
            for i, leak in enumerate(format_leaks[:10]):  # Limit to first 10
                format_text += f"- Leak {i+1}: {leak.get('address')} (using payload: {leak.get('payload')})\n"
            if len(format_leaks) > 10:
                format_text += f"[...and {len(format_leaks) - 10} more leaks...]"
        else:
            format_text = "No format string leaks detected."
        
        # Format crash analysis
        crash_analysis = results.get("crash_analysis", {})
        if crash_analysis.get("crashed", False):
            crash_text = "Binary crashed during testing.\n"
            if "controlled_pc" in crash_analysis and crash_analysis["controlled_pc"]:
                crash_text += f"Program counter (EIP/RIP) controlled at offset: {crash_analysis.get('pc_offset')}\n"
            
            crash_text += "Register values at crash:\n"
            for reg, value in crash_analysis.get("registers", {}).items():
                crash_text += f"- {reg}: {hex(value)}\n"
            
            crash_text += "\nBacktrace:\n"
            for bt_line in crash_analysis.get("backtrace", [])[:5]:  # First 5 backtrace lines
                crash_text += f"{bt_line}\n"
        else:
            crash_text = "Binary did not crash during testing."
        
        # Format libc base
        libc_base = results.get("libc_base")
        if libc_base:
            libc_text = f"Libc base address: {hex(libc_base)}"
        else:
            libc_text = "Libc base address not found."
        
        # Format ROP gadgets (just a sample for the LLM)
        rop_gadgets = results.get("rop_gadgets", [])
        if rop_gadgets:
            rop_text = f"Found {len(rop_gadgets)} potential ROP gadgets. Some useful ones:\n"
            # Categorize gadgets by instruction for better readability
            categorized = {}
            for gadget in rop_gadgets:
                instr = gadget.get("instruction", "")
                if instr not in categorized:
                    categorized[instr] = []
                categorized[instr].append(gadget.get("address"))
            
            # Add a sample of gadgets (to avoid token overload)
            count = 0
            for instr, addresses in categorized.items():
                if count >= 10:  # Limit to 10 types of gadgets
                    break
                addr_str = ', '.join(addresses[:3])  # Show up to 3 addresses per gadget
                if len(addresses) > 3:
                    addr_str += f", ... ({len(addresses) - 3} more)"
                rop_text += f"- {instr}: {addr_str}\n"
                count += 1
        else:
            rop_text = "No ROP gadgets found."
        
        # Format the prompt
        formatted_prompt = prompt.format(
            security_features=security_text,
            overflow_info=overflow_text,
            format_leaks=format_text,
            crash_analysis=crash_text,
            libc_base=libc_text,
            rop_gadgets=rop_text,
        )
        
        # Call LLM
        self.logger.debug("Sending analysis request to LLM")
        response = self.llm.call(formatted_prompt)
        
        return response
    
    def _make_serializable(self, obj: Any) -> Any:
        """
        Make an object JSON-serializable by converting non-serializable types.
        
        Args:
            obj: The object to make serializable
            
        Returns:
            A serializable version of the object
        """
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        elif isinstance(obj, bytes):
            return obj.decode('latin1')
        else:
            return str(obj) 