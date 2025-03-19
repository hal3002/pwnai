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
from pwn import process


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
        llm_service: Optional[LLMService] = None,
    ):
        """
        Initialize the Debugging Agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM
            llm_service: Optional shared LLM service instance
        """
        super().__init__(state, binary_path, output_dir, llm_config, llm_service)
        
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
        
        # Initialize LLM service if not provided
        if self.llm_service is None:
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
        else:
            self.llm = self.llm_service
    
    # Constants for tasks
    DEBUGGING_TASKS = [
        "find_overflow_offset",
        "find_format_string_offset",
        "find_format_string_leak",
        "analyze_crash",
        "find_gadgets",
        "leak_addresses",
        "get_libc_base",
        "help_calculate_win_address"
    ]
    
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
            tasks = self._plan_debugging_tasks()
        
        # Initialize results
        results = {}
        
        try:
            # Run security checks
            security_features = self.gdb.check_security()
            self.logger.info(f"Security features: {security_features}")
            results["security_features"] = security_features
            
            # Update state with security features for other agents
            self.update_state({
                "has_nx": security_features.get("nx", False),
                "has_canary": security_features.get("canary", False),
                "has_pie": security_features.get("pie", False),
                "has_relro": security_features.get("relro", False)
            })
            
            # Process each task with error handling
            for task in tasks:
                self.logger.info(f"Running debugging task: {task}")
                
                try:
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
                        libc_base = self._get_libc_base()
                        results["libc_base"] = libc_base
                    
                    elif task == "analyze_crash":
                        crash_analysis = self._analyze_crash()
                        results["crash_analysis"] = crash_analysis
                        
                        # If we found overflow via crash analysis but not via direct detection
                        if (results.get("overflow_offset") is None and 
                            crash_analysis.get("overflow_found", False)):
                            # Use the PC offset if available
                            if "pc_offset" in crash_analysis:
                                results["overflow_offset"] = crash_analysis["pc_offset"]
                                results["overflow_message"] = f"Found overflow offset at {crash_analysis['pc_offset']} bytes from crash analysis"
                                self.logger.info(f"Using overflow offset from crash analysis: {crash_analysis['pc_offset']} bytes")
                            # Use register offset as fallback
                            elif "reg_offset" in crash_analysis:
                                results["overflow_offset"] = crash_analysis["reg_offset"]
                                results["overflow_message"] = f"Found overflow offset at {crash_analysis['reg_offset']} bytes (controls {crash_analysis.get('controlled_reg', 'register')})"
                                self.logger.info(f"Using register offset from crash analysis: {crash_analysis['reg_offset']} bytes")
                            # Use stack offset as last resort
                            elif "stack_offset" in crash_analysis:
                                results["overflow_offset"] = crash_analysis["stack_offset"]
                                results["overflow_message"] = f"Found overflow offset at {crash_analysis['stack_offset']} bytes (pattern on stack)"
                                self.logger.info(f"Using stack offset from crash analysis: {crash_analysis['stack_offset']} bytes")
                except Exception as e:
                    self.logger.error(f"Error in task {task}: {str(e)}")
                    results[f"{task}_error"] = str(e)
            
            # Generate output even if not all tasks succeeded
            if any(task in results for task in tasks) or results.get("security_features"):
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
            else:
                self.logger.warning("No useful debugging results were obtained")
                results["no_results"] = True
                
        except Exception as e:
            self.logger.error(f"Error in dynamic analysis: {str(e)}")
            # Make sure we still return something useful even if we failed
            results["error"] = str(e)
            self.update_state({"debug_error": str(e)})
        
        return self.state
    
    def _plan_debugging_tasks(self) -> List[str]:
        """
        Use LLM to determine which debugging tasks to execute.
        
        Returns:
            List of task names to execute
        """
        # Get vulnerability info from state
        vuln_type = self.get_state_value("vulnerability_type", "unknown")
        vuln_details = self.get_state_value("vulnerability_details", {})
        vulns = self.get_state_value("vulnerabilities", [])
        
        # Security features
        security = self.get_state_value("security_features", {})
        
        # Construct a prompt for the LLM
        prompt = f"""
        I'm debugging a binary with a potential {vuln_type} vulnerability.
        
        Security features:
        - NX (No-Execute): {security.get('nx', 'unknown')}
        - Stack Canary: {security.get('canary', 'unknown')}
        - PIE (Position Independent Executable): {security.get('pie', 'unknown')}
        - RELRO: {security.get('relro', 'unknown')}
        
        Vulnerability details: {vuln_details}
        
        I need to determine which of the following debugging tasks would be most useful:
        - find_overflow_offset: Determine the offset needed to overflow a buffer and control program execution
        - find_format_string_offset: Find the offset in a format string vulnerability
        - analyze_crash: Run the program with a pattern and analyze the crash
        - find_gadgets: Identify useful ROP gadgets in the binary
        - leak_addresses: Attempt to leak addresses from the binary
        - help_calculate_win_address: Find and calculate addresses needed for exploitation
        
        Based on the vulnerability type and security features, which tasks would be most valuable? 
        Return a comma-separated list of task names, in priority order.
        """
        
        # Incorporate user feedback if available
        prompt = self.incorporate_feedback(prompt)
        
        # Incorporate source file if available
        prompt = self.incorporate_source(prompt)
        
        # If we have specific vulnerabilities, incorporate the feedback from the first one
        if vulns and isinstance(vulns[0], dict):
            prompt = self.incorporate_vulnerability_feedback(prompt, vulns[0])
        
        # Call LLM
        self.logger.debug("Determining debugging tasks...")
        response = self.llm.call(prompt)
        
        # Parse response (expecting comma-separated list)
        tasks = [task.strip() for task in response.split(",")]
        
        # Filter to known tasks and remove duplicates while preserving order
        valid_tasks = []
        for task in tasks:
            # Clean up task name (remove extra text, quotes, etc.)
            task_name = task.strip().lower()
            # Extract just the task name if there's other text
            for known_task in self.DEBUGGING_TASKS:
                if known_task in task_name and known_task not in valid_tasks:
                    valid_tasks.append(known_task)
                    break
        
        # If no valid tasks were found, use default tasks
        if not valid_tasks:
            self.logger.warning("No valid tasks determined, using default tasks")
            return ["find_overflow_offset", "find_gadgets", "analyze_crash"]
        
        return valid_tasks
    
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
        
        # Make sure binary_path exists and is valid
        if not self.binary_path or not os.path.exists(self.binary_path):
            self.logger.warning(f"Binary path does not exist: {self.binary_path}")
            return leaked_addresses
            
        binary_path_str = str(self.binary_path)
        
        for payload in payloads:
            try:
                # Run the binary directly with process() instead of using GDB
                self.logger.debug(f"Testing format string payload: {payload}")
                p = process([binary_path_str])
                
                # Send the payload
                p.sendline(payload)
                
                # Collect output
                try:
                    output = p.recvall(timeout=5)  # Use a shorter timeout
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
                    self.logger.warning(f"Error collecting output for format string leak: {str(e)}")
                finally:
                    try:
                        p.close()
                    except:
                        pass
                    
            except Exception as e:
                self.logger.warning(f"Error during format string leak test: {str(e)}")
        
        # Return any addresses we found
        return leaked_addresses
    
    def _get_libc_base(self) -> Optional[int]:
        """
        Try to get the base address of libc.
        
        Returns:
            Base address of libc or None if not found
        """
        try:
            libc_base = self.gdb.get_libc_base()
            if libc_base is not None:
                self.logger.info(f"Found libc base address: {hex(libc_base) if libc_base != 0 else 'dynamically linked'}")
                return libc_base
            else:
                self.logger.info("Could not determine libc base address")
                return None
        except Exception as e:
            self.logger.warning(f"Error getting libc base: {str(e)}")
            return None
    
    def _analyze_crash(self) -> Dict[str, Any]:
        """
        Run the binary until it crashes and analyze the crash.
        
        Returns:
            Dictionary with crash analysis information
        """
        # Create a cyclic pattern to potentially trigger a crash
        from pwn import cyclic
        pattern = cyclic(1024)
        
        # Add newline if needed
        if isinstance(pattern, bytes) and not pattern.endswith(b'\n'):
            pattern += b'\n'
        
        # Set up GDB commands - try with a breakpoint at main first
        gdb_commands = [
            "set pagination off",
            "set height 0",
            "set width 0",
            "break main",  # Break at main to ensure program is loaded
            "run",  # Run until the breakpoint
            "continue",  # Continue execution to allow input
            "bt",  # Backtrace on crash
            "info registers",  # Register state
            "x/32wx $sp",  # Examine stack
            "quit",  # Make sure GDB exits
        ]
        
        # Run the binary
        try:
            self.logger.debug("Running binary with cyclic pattern to analyze crash")
            stdout, stderr = self.gdb.debug_binary(
                gdb_commands=gdb_commands,
                stdin=pattern.decode('latin1')
            )
            
            # If no crash on first attempt, try without breaking at main
            if "SIGSEGV" not in stdout and "segmentation fault" not in stdout.lower():
                self.logger.debug("No crash detected, trying direct run approach")
                gdb_commands = [
                    "set pagination off",
                    "set height 0",
                    "set width 0",
                    "run",  # Run directly
                    "bt",  # Backtrace on crash
                    "info registers",  # Register state
                    "x/32wx $sp",  # Examine stack
                    "quit",  # Make sure GDB exits
                ]
                
                stdout, stderr = self.gdb.debug_binary(
                    gdb_commands=gdb_commands,
                    stdin=pattern.decode('latin1')
                )
            
            # Parse the output for crash information
            result = {
                "crashed": "SIGSEGV" in stdout or "SIGABRT" in stdout or "segmentation fault" in stdout.lower(),
                "output": stdout[:2000],  # Limit output size
                "registers": {},
                "backtrace": [],
                "stack": []
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
            
            # Extract stack data
            stack_section = False
            stack_values = []
            stack_pattern = r'0x[0-9a-f]+:\s+((?:0x[0-9a-f]+\s+)+)'
            for line in stdout.splitlines():
                if 'x/32wx $sp' in line:
                    stack_section = True
                    continue
                if stack_section:
                    match = re.search(stack_pattern, line)
                    if match:
                        values = match.group(1).strip().split()
                        stack_values.extend(values)
                    else:
                        if not re.search(r'0x[0-9a-f]+:', line):
                            stack_section = False
            
            # Convert stack values to integers
            result["stack"] = [int(v, 16) if v.startswith('0x') else int(v) for v in stack_values]
            
            # Check if we control EIP/RIP
            for reg in ["eip", "rip", "pc"]:  # Add "pc" for ARM
                if reg in result["registers"]:
                    try:
                        # Check if the register value is part of our pattern
                        from pwn import cyclic_find
                        reg_value = result["registers"][reg]
                        
                        # Log the register value for debugging
                        self.logger.debug(f"Checking if {reg}=0x{reg_value:x} is in pattern")
                        
                        # Try direct value first
                        offset = cyclic_find(reg_value)
                        if offset >= 0:
                            result["controlled_pc"] = True
                            result["pc_offset"] = offset
                            self.logger.info(f"Found pattern at offset {offset} in {reg.upper()}")
                            break
                        
                        # Try with packed value (for 64-bit)
                        from pwn import p32
                        offset = cyclic_find(p32(reg_value & 0xffffffff))
                        if offset >= 0:
                            result["controlled_pc"] = True
                            result["pc_offset"] = offset
                            self.logger.info(f"Found pattern at offset {offset} in {reg.upper()} (packed)")
                            break
                            
                        # Try different sections of the value
                        for i in range(4):
                            val_slice = (reg_value >> (i*8)) & 0xffffffff
                            if val_slice == 0:
                                continue
                                
                            offset = cyclic_find(val_slice)
                            if offset >= 0:
                                result["controlled_pc"] = True
                                result["pc_offset"] = offset - i
                                self.logger.info(f"Found pattern slice at offset {offset-i} in {reg.upper()}")
                                break
                        
                    except Exception as e:
                        self.logger.warning(f"Error checking PC control: {str(e)}")
            
            # If we haven't found PC control yet, check other registers
            if not result.get("controlled_pc"):
                for reg_name, reg_value in result["registers"].items():
                    if reg_name in ["eip", "rip", "pc"]:
                        continue  # Already checked these
                    
                    try:
                        # Check direct value
                        offset = cyclic_find(reg_value)
                        if offset >= 0:
                            result["controlled_reg"] = reg_name
                            result["reg_offset"] = offset
                            self.logger.info(f"Found pattern at offset {offset} in {reg_name.upper()}")
                            break
                            
                        # Try packed value
                        offset = cyclic_find(p32(reg_value & 0xffffffff))
                        if offset >= 0:
                            result["controlled_reg"] = reg_name
                            result["reg_offset"] = offset
                            self.logger.info(f"Found pattern at offset {offset} in {reg_name.upper()} (packed)")
                            break
                    except Exception:
                        pass
            
            # If still no control found, check stack values
            if not result.get("controlled_pc") and not result.get("controlled_reg") and result["stack"]:
                for i, stack_val in enumerate(result["stack"]):
                    try:
                        offset = cyclic_find(stack_val)
                        if offset >= 0:
                            result["pattern_on_stack"] = True
                            result["stack_offset"] = offset
                            result["stack_position"] = i*4  # Assuming 4-byte stack entries
                            self.logger.info(f"Found pattern at offset {offset} on stack at position {i*4}")
                            break
                            
                        # Try packed value
                        offset = cyclic_find(p32(stack_val & 0xffffffff))
                        if offset >= 0:
                            result["pattern_on_stack"] = True
                            result["stack_offset"] = offset
                            result["stack_position"] = i*4
                            self.logger.info(f"Found pattern at offset {offset} on stack at position {i*4} (packed)")
                            break
                    except Exception:
                        pass
            
            # If we found any kind of overflow, consider it successful
            if result.get("controlled_pc") or result.get("controlled_reg") or result.get("pattern_on_stack"):
                result["overflow_found"] = True
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during crash analysis: {str(e)}")
            return {
                "crashed": False,
                "error": str(e),
                "output": "Error during crash analysis",
                "registers": {},
                "backtrace": [],
                "stack": []
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
    
    def _find_overflow_offset_with_common_values(self) -> Tuple[Optional[int], str]:
        """
        Try common buffer sizes to find an overflow offset when automated detection fails.
        
        Returns:
            Tuple of (offset if found, or None; log message)
        """
        # Common buffer sizes to try - ordered by frequency
        common_sizes = [64, 72, 76, 80, 88, 100, 104, 112, 128]
        
        self.logger.info(f"Trying common buffer sizes: {common_sizes}")
        
        # Try each size
        for size in common_sizes:
            # Create a pattern of 'A's of the given size, plus 'BBBB' to overwrite EIP
            pattern = b'A' * size + b'BBBB'
            
            # Add marker before and after to help identify truncation
            payload = b'PWNAI-' + pattern + b'-PWNAI'
            
            # Run the binary with this pattern
            gdb_commands = [
                "set pagination off",
                "set height 0",
                "set width 0", 
                "run",  # Run directly
                "bt",   # Backtrace
                "info registers", # Register dump
                "quit",
            ]
            
            # Debug with the pattern
            stdout, stderr = self.gdb.debug_binary(gdb_commands=gdb_commands, stdin=payload)
            
            # Check if we caused a segfault
            if "SIGSEGV" in stdout or "segmentation fault" in stdout.lower():
                # Check if EIP/RIP contains our marker ('BBBB' = 0x42424242)
                eip_marker = "0x42424242"
                if eip_marker in stdout:
                    self.logger.info(f"Found overflow with buffer size {size} (EIP controlled with BBBB)")
                    return size, f"Found overflow offset at {size} bytes using common buffer size testing"
            
            # Short delay to not overwhelm the system
            import time
            time.sleep(0.5)
        
        # If no common size worked, return the most likely size based on static analysis
        # For 32-bit binaries, local buffers are often aligned to 64-byte boundaries
        if "i386" in self.gdb.elf.arch or "x86" in self.gdb.elf.arch:
            self.logger.info("No common size worked, suggesting 76 bytes based on x86 stack alignment")
            return 76, "Suggesting 76 bytes as probable offset based on x86 analysis"
        else:
            # For 64-bit, suggest 96 bytes which is common
            self.logger.info("No common size worked, suggesting 96 bytes based on x86_64 stack alignment")
            return 96, "Suggesting 96 bytes as probable offset based on x86_64 analysis" 