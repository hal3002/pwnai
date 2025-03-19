"""
Writeup Agent for PwnAI.

This agent is responsible for generating detailed documentation/writeups
of the exploitation process.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pwnai.agents.base_agent import BaseAgent
from pwnai.utils.llm_service import LLMService


class WriteupAgent(BaseAgent):
    """
    Agent for generating detailed writeups and documentation.
    
    This agent collects information from all other agents and generates
    a comprehensive writeup of the exploitation process.
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
        Initialize the Writeup Agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM
            llm_service: Optional shared LLM service instance
        """
        super().__init__(state, binary_path, output_dir, llm_config, llm_service)
        
        # Initialize LLM service if not provided
        if self.llm_service is None:
            llm_system_prompt = """
            You are an expert binary exploitation documentalist. Your job is to create detailed, 
            educational writeups for Capture The Flag (CTF) challenges. These writeups should explain 
            the entire process of identifying, analyzing, and exploiting vulnerabilities in binaries.
            
            Your writeups should be clear, comprehensive, and follow a logical progression. They should 
            provide enough detail that someone with basic knowledge of binary exploitation could understand 
            and learn from the explanation. Include:
            
            1. Initial analysis and discovery of the vulnerability
            2. A technical explanation of the vulnerability
            3. The process of developing the exploit
            4. The final exploit and how it works
            5. General lessons that can be applied to similar challenges
            
            Use a professional yet accessible tone, and organize the content with clear sections and headings.
            """
            
            self.llm = LLMService(
                system_prompt=llm_system_prompt,
                **(llm_config or {})
            )
        else:
            self.llm = self.llm_service
            
        # For compatibility with some methods that expect a model parameter
        self.model = None
    
    def run(self) -> Dict[str, Any]:
        """
        Generate a solution writeup.
        
        Returns:
            Dictionary containing the writeup
        """
        self.logger.info("Generating exploitation writeup")
        
        # Generate the main writeup
        writeup = self._generate_writeup()
        
        # Save the writeup to disk
        writeup_path = self.output_dir / "writeup.md"
        with open(writeup_path, "w") as f:
            f.write(writeup)
        
        self.logger.info(f"Saved writeup to {writeup_path}")
        
        # Generate a summary for easy reference
        summary = self._generate_summary(writeup)
        
        # Save the summary to disk
        summary_path = self.output_dir / "writeup_summary.md"
        with open(summary_path, "w") as f:
            f.write(summary)
        
        self.logger.info(f"Saved summary writeup to {summary_path}")
        
        # Update state with the writeup
        self.update_state({
            "writeup": writeup,
            "writeup_summary": summary
        })
        
        return self.state
    
    def _read_file(self, path: Path) -> str:
        """
        Read a file safely, returning empty string if file not found.
        
        Args:
            path: Path to the file
            
        Returns:
            File contents as string, or empty string if file not found
        """
        try:
            if path.exists():
                with open(path, "r") as f:
                    return f.read()
            else:
                self.logger.warning(f"File not found: {path}")
                return "[File not available]"
        except Exception as e:
            self.logger.error(f"Error reading file {path}: {str(e)}")
            return f"[Error reading file: {str(e)}]"
    
    def _generate_writeup(self) -> str:
        """
        Generate a comprehensive writeup of the exploitation process.
        
        Returns:
            Markdown-formatted writeup
        """
        # Collect all available information
        binary_path = self.state.get("binary_path", "unknown")
        binary_arch = self.state.get("architecture", {})
        security_features = self.state.get("security_features", {})
        vulnerabilities = self.state.get("vulnerabilities", [])
        vulnerability_type = self.state.get("vulnerability_type", "unknown")
        exploitation_plan = self._read_file(self.output_dir / "exploitation_plan.txt")
        debug_analysis = self._read_file(self.output_dir / "debug_analysis.txt")
        reversing_analysis = self._read_file(self.output_dir / "vulnerability_analysis.txt")
        exploit_code = self._read_file(self.output_dir / "exploit.py")
        exploit_success = self.state.get("exploit_successful", False)
        flag = self.state.get("flag", "Not found")
        
        # Read source file if available
        source_code = self.read_source_file()
        source_section = ""
        if source_code:
            source_section = f"""
        ## SOURCE CODE
        ```c
        {source_code}
        ```
        """
        
        # Format information for the LLM prompt
        prompt = f"""
        Please write a detailed CTF writeup for the binary {os.path.basename(binary_path)}.
        Include all the necessary sections such as introduction, vulnerability analysis, 
        exploitation process, and conclusion.
        
        Here's the information I have:
        
        ## BINARY INFO
        - Architecture: {binary_arch.get("arch", "unknown")} {binary_arch.get("bits", "")}
        - Security Features:
          - NX: {security_features.get("nx", "unknown")}
          - Canary: {security_features.get("canary", "unknown")}
          - PIE: {security_features.get("pie", "unknown")}
          - RELRO: {security_features.get("relro", "unknown")}
        
        ## VULNERABILITIES
        - Primary vulnerability: {vulnerability_type}
        - Vulnerability details follow below in the analysis sections
        {source_section}
        ## STATIC ANALYSIS
        {reversing_analysis}
        
        ## DYNAMIC ANALYSIS
        {debug_analysis}
        
        ## EXPLOITATION PLAN
        {exploitation_plan}
        
        ## EXPLOIT CODE
        ```python
        {exploit_code}
        ```
        
        ## RESULT
        - Exploit success: {exploit_success}
        - Flag: {flag}
        
        Format the writeup in markdown with appropriate sections, code blocks, and explanations.
        Make sure to detail the entire process from initial analysis to exploitation.
        Include any relevant addresses, offsets, and techniques used.
        Explain why certain approaches were taken and how they relate to the binary's security measures.
        """
        
        # Incorporate user feedback if available
        prompt = self.incorporate_feedback(prompt)
        
        # If we have specific vulnerabilities, incorporate the feedback from the first one
        if vulnerabilities and isinstance(vulnerabilities[0], dict):
            prompt = self.incorporate_vulnerability_feedback(prompt, vulnerabilities[0])
        
        # Call LLM
        self.logger.info("Generating writeup...")
        writeup = self.llm.call(prompt, model=self.model)
        
        return writeup
    
    def _collect_binary_info(self) -> Dict[str, Any]:
        """
        Collect information about the binary from the state.
        
        Returns:
            Dictionary with binary information
        """
        info = {
            "path": str(self.binary_path),
            "architecture": self.get_from_state("architecture", {}),
            "security_features": self.get_from_state("security_features", {}),
        }
        
        # Try to get from debug results if not directly in state
        debug_results = self.get_from_state("debug_results", {})
        if not info["security_features"] and "security_features" in debug_results:
            info["security_features"] = debug_results["security_features"]
        
        return info
    
    def _collect_vulnerability_info(self) -> Dict[str, Any]:
        """
        Collect information about the vulnerabilities from the state.
        
        Returns:
            Dictionary with vulnerability information
        """
        return {
            "vulnerabilities": self.get_from_state("vulnerabilities", []),
            "vulnerability_analysis": self.get_from_state("vulnerability_analysis", ""),
        }
    
    def _collect_debugging_info(self) -> Dict[str, Any]:
        """
        Collect debugging information from the state.
        
        Returns:
            Dictionary with debugging information
        """
        debug_results = self.get_from_state("debug_results", {})
        return {
            "debug_results": debug_results,
            "debug_analysis": debug_results.get("debug_analysis", ""),
        }
    
    def _collect_exploitation_info(self) -> Dict[str, Any]:
        """
        Collect exploitation information from the state.
        
        Returns:
            Dictionary with exploitation information
        """
        return {
            "exploitation_plan": self.get_from_state("exploitation_plan", ""),
            "exploit_script": self.get_from_state("exploit_script", ""),
            "exploit_summary": self.get_from_state("exploit_summary", ""),
            "exploit_test_success": self.get_from_state("exploit_test_success", False),
            "exploit_test_output": self.get_from_state("exploit_test_output", ""),
        }
    
    def _generate_introduction(self, binary_info: Dict[str, Any]) -> str:
        """
        Generate the introduction section of the writeup.
        
        Args:
            binary_info: Information about the binary
            
        Returns:
            Formatted introduction section
        """
        prompt = """
        Please write an introduction section for a CTF challenge writeup. This should include:
        
        1. A brief overview of the challenge
        2. The technical specifications of the binary
        3. The security features enabled/disabled
        4. A high-level summary of the vulnerability and exploitation approach
        
        ## BINARY INFORMATION
        - Path: {path}
        - Architecture: {arch} {bits}-bit
        - Security Features:
          {security_features}
        
        Make the introduction engaging and professional. It should set the stage for the detailed 
        analysis that follows. Keep it to 2-3 paragraphs.
        """
        
        arch_info = binary_info.get("architecture", {})
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 0)
        
        # Format security features
        security_features = binary_info.get("security_features", {})
        security_text = ""
        for k, v in security_features.items():
            security_text += f"  - {k.upper()}: {v}\n"
        
        if not security_text:
            security_text = "  - No security information available\n"
        
        formatted_prompt = prompt.format(
            path=binary_info.get("path", "unknown"),
            arch=arch,
            bits=bits,
            security_features=security_text,
        )
        
        return self.llm.call(formatted_prompt)
    
    def _generate_vulnerability_analysis(self, vulnerability_info: Dict[str, Any]) -> str:
        """
        Generate the vulnerability analysis section of the writeup.
        
        Args:
            vulnerability_info: Information about the vulnerabilities
            
        Returns:
            Formatted vulnerability analysis section
        """
        prompt = """
        Please write a detailed vulnerability analysis section for a CTF challenge writeup. This should include:
        
        1. A description of the vulnerability discovery process
        2. Technical details of each vulnerability found
        3. Code snippets or assembly highlighting the vulnerable parts (if available)
        4. An explanation of why the code is vulnerable
        
        ## VULNERABILITIES FOUND
        {vulnerabilities}
        
        ## VULNERABILITY ANALYSIS
        {vulnerability_analysis}
        
        Make this section technical but clear, explaining how each vulnerability works and how it can be leveraged
        for exploitation. Use proper technical terminology and be precise in your explanations.
        """
        
        # Format vulnerabilities
        vulnerabilities = vulnerability_info.get("vulnerabilities", [])
        vuln_text = ""
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                vuln_text += f"{i+1}. Type: {vuln.get('type', 'unknown')}\n"
                for k, v in vuln.items():
                    if k != "type":
                        vuln_text += f"   - {k}: {v}\n"
                vuln_text += "\n"
        else:
            vuln_text = "No specific vulnerabilities identified.\n"
        
        # Get the vulnerability analysis text
        analysis_text = vulnerability_info.get("vulnerability_analysis", "")
        if not analysis_text:
            analysis_text = "No detailed vulnerability analysis available."
        
        formatted_prompt = prompt.format(
            vulnerabilities=vuln_text,
            vulnerability_analysis=analysis_text,
        )
        
        return self.llm.call(formatted_prompt)
    
    def _generate_exploitation_process(
        self,
        debugging_info: Dict[str, Any],
        exploitation_info: Dict[str, Any],
    ) -> str:
        """
        Generate the exploitation process section of the writeup.
        
        Args:
            debugging_info: Information from debugging
            exploitation_info: Information about the exploitation process
            
        Returns:
            Formatted exploitation process section
        """
        prompt = """
        Please write a detailed section describing the process of developing the exploit for this CTF challenge.
        This should include:
        
        1. The debugging process and key findings
        2. The exploitation strategy and why it was chosen
        3. Step-by-step explanation of the exploit development
        4. Any challenges encountered and how they were overcome
        
        ## DEBUGGING INFORMATION
        {debug_info}
        
        ## EXPLOITATION PLAN
        {exploitation_plan}
        
        Make this section read like a journey from vulnerability discovery to working exploit. Explain the reasoning
        behind each decision and include technical details that would help readers understand the approach. This
        section should be the most detailed part of the writeup.
        """
        
        # Format debugging information
        debug_results = debugging_info.get("debug_results", {})
        debug_analysis = debugging_info.get("debug_analysis", "")
        
        debug_info = "### Key Debugging Findings:\n"
        
        if "overflow_offset" in debug_results and debug_results["overflow_offset"] is not None:
            debug_info += f"- Buffer Overflow Offset: {debug_results['overflow_offset']} bytes\n"
        
        if "leaked_addresses" in debug_results and debug_results["leaked_addresses"]:
            debug_info += f"- Found {len(debug_results['leaked_addresses'])} leaked addresses\n"
        
        if "libc_base" in debug_results and debug_results["libc_base"]:
            debug_info += f"- Libc Base Address: {hex(debug_results['libc_base'])}\n"
        
        if "rop_gadgets" in debug_results and debug_results["rop_gadgets"]:
            debug_info += f"- Found {len(debug_results['rop_gadgets'])} potential ROP gadgets\n"
        
        crash_analysis = debug_results.get("crash_analysis", {})
        if crash_analysis.get("crashed", False):
            debug_info += "- Binary crashed during testing\n"
            if "controlled_pc" in crash_analysis and crash_analysis["controlled_pc"]:
                debug_info += f"- Program counter (EIP/RIP) controlled at offset: {crash_analysis.get('pc_offset')}\n"
        
        debug_info += "\n### Debugging Analysis:\n"
        debug_info += debug_analysis or "No detailed debugging analysis available."
        
        # Get the exploitation plan
        exploitation_plan = exploitation_info.get("exploitation_plan", "")
        if not exploitation_plan:
            exploitation_plan = "No detailed exploitation plan available."
        
        formatted_prompt = prompt.format(
            debug_info=debug_info,
            exploitation_plan=exploitation_plan,
        )
        
        return self.llm.call(formatted_prompt, max_tokens=2048)
    
    def _generate_final_exploit(self, exploitation_info: Dict[str, Any]) -> str:
        """
        Generate the final exploit section of the writeup.
        
        Args:
            exploitation_info: Information about the exploitation
            
        Returns:
            Formatted final exploit section
        """
        prompt = """
        Please write a section detailing the final exploit for this CTF challenge. This should include:
        
        1. A breakdown of the final exploit script
        2. An explanation of each component of the exploit
        3. How to run the exploit and what to expect
        4. The results of testing the exploit
        
        ## EXPLOIT SCRIPT
        ```python
        {exploit_script}
        ```
        
        ## EXPLOIT SUMMARY
        {exploit_summary}
        
        ## TESTING RESULTS
        Success: {success}
        
        {test_output}
        
        Make this section clear and technically precise. Explain how the exploit works at a low level and how 
        all the components fit together. Include any specific addresses, offsets, or bytecode used in the exploit.
        """
        
        # Get the exploit script
        exploit_script = exploitation_info.get("exploit_script", "")
        if not exploit_script:
            exploit_script = "# No exploit script available"
        
        # Get the exploit summary
        exploit_summary = exploitation_info.get("exploit_summary", "")
        if not exploit_summary:
            exploit_summary = "No detailed exploit summary available."
        
        # Get test results
        success = exploitation_info.get("exploit_test_success", False)
        test_output = exploitation_info.get("exploit_test_output", "")
        
        if not test_output:
            test_output = "No test output available."
        elif len(test_output) > 1000:
            # Truncate long test output
            test_output = test_output[:1000] + "...\n[output truncated for brevity]"
        
        formatted_prompt = prompt.format(
            exploit_script=exploit_script,
            exploit_summary=exploit_summary,
            success=success,
            test_output=test_output,
        )
        
        return self.llm.call(formatted_prompt, max_tokens=2048)
    
    def _generate_conclusion(
        self,
        binary_info: Dict[str, Any],
        vulnerability_info: Dict[str, Any],
    ) -> str:
        """
        Generate the conclusion section of the writeup.
        
        Args:
            binary_info: Information about the binary
            vulnerability_info: Information about the vulnerabilities
            
        Returns:
            Formatted conclusion section
        """
        prompt = """
        Please write a conclusion section for a CTF challenge writeup. This should include:
        
        1. A summary of what was learned from the challenge
        2. Generalizations that can be applied to similar challenges
        3. Mitigation strategies that could have prevented the vulnerability
        4. Any final thoughts or takeaways
        
        ## BINARY INFORMATION
        - Architecture: {arch} {bits}-bit
        - Security Features:
          {security_features}
        
        ## VULNERABILITIES FOUND
        {vulnerabilities}
        
        Make this section reflective and educational. It should tie together the whole writeup and leave 
        the reader with clear takeaways. Keep it concise but insightful.
        """
        
        arch_info = binary_info.get("architecture", {})
        arch = arch_info.get("arch", "unknown")
        bits = arch_info.get("bits", 0)
        
        # Format security features
        security_features = binary_info.get("security_features", {})
        security_text = ""
        for k, v in security_features.items():
            security_text += f"  - {k.upper()}: {v}\n"
        
        if not security_text:
            security_text = "  - No security information available\n"
        
        # Format vulnerabilities (brief version)
        vulnerabilities = vulnerability_info.get("vulnerabilities", [])
        vuln_text = ""
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                vuln_text += f"{i+1}. Type: {vuln.get('type', 'unknown')}\n"
        else:
            vuln_text = "No specific vulnerabilities identified.\n"
        
        formatted_prompt = prompt.format(
            arch=arch,
            bits=bits,
            security_features=security_text,
            vulnerabilities=vuln_text,
        )
        
        return self.llm.call(formatted_prompt)
    
    def _combine_sections(self, sections: Dict[str, str]) -> str:
        """
        Combine all sections into a complete writeup.
        
        Args:
            sections: Dictionary of section names to section text
            
        Returns:
            Complete writeup as text
        """
        # Define the order and headings
        section_order = [
            ("introduction", "# Introduction"),
            ("vulnerability_analysis", "# Vulnerability Analysis"),
            ("exploitation_process", "# Exploitation Process"),
            ("final_exploit", "# Final Exploit"),
            ("conclusion", "# Conclusion"),
        ]
        
        # Combine sections
        writeup = f"# CTF Challenge Writeup: {self.binary_path.name}\n\n"
        
        for section_name, heading in section_order:
            section_text = sections.get(section_name, "")
            if section_text:
                writeup += heading + "\n\n"
                writeup += section_text + "\n\n"
        
        return writeup
    
    def _generate_summary(self, full_writeup: str) -> str:
        """
        Generate a shorter summary version of the writeup.
        
        Args:
            full_writeup: The complete writeup text
            
        Returns:
            Summary version of the writeup
        """
        prompt = """
        Please create a concise summary version of the following CTF challenge writeup. The summary should:
        
        1. Capture the key points of each section
        2. Be approximately 1/3 the length of the original
        3. Maintain the technical accuracy while being more concise
        4. Keep the same section structure but with shorter content
        
        ## ORIGINAL WRITEUP
        {writeup}
        
        Make the summary professional and informative, focusing on the most important technical details.
        """
        
        formatted_prompt = prompt.format(writeup=full_writeup)
        
        return self.llm.call(formatted_prompt, max_tokens=4096) 