"""
Reversing Agent for PwnAI.

This agent is responsible for performing static analysis on binaries
to identify potential vulnerabilities.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pwnai.agents.base_agent import BaseAgent
from pwnai.tools.radare2 import Radare2
from pwnai.utils.llm_service import LLMService


class ReversingAgent(BaseAgent):
    """
    Agent for reversing and static analysis of binaries.
    
    This agent uses Radare2 to perform static analysis and identify
    potential vulnerabilities in the target binary.
    """
    
    def __init__(
        self,
        state: Dict[str, Any],
        binary_path: Path,
        output_dir: Path,
        llm_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the Reversing Agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM
        """
        super().__init__(state, binary_path, output_dir, llm_config)
        
        # Initialize Radare2 wrapper
        self.r2 = Radare2(binary_path)
        
        # Initialize LLM service
        llm_system_prompt = """
        You are a binary exploitation and reverse engineering expert. You have deep knowledge of 
        assembly, binary formats (ELF, etc.), memory corruption vulnerabilities, and exploitation techniques.
        
        You are given information about a binary that needs to be analyzed for vulnerabilities. 
        Thoroughly analyze the provided disassembly, strings, symbols, and other information.
        Focus on identifying potential vulnerabilities such as:
        
        1. Buffer overflows (look for unbounded input functions like gets, strcpy, etc.)
        2. Format string vulnerabilities (printf with user-controlled format string)
        3. Integer overflows
        4. Use-after-free issues
        5. Logic bugs or hardcoded credentials
        
        For each potential vulnerability, identify:
        - The type of vulnerability
        - The location (function, address)
        - The input vector (how user input reaches the vulnerability)
        - Any relevant constraints or security mitigations
        
        Return your analysis in a structured format that explains the findings clearly.
        """
        
        self.llm = LLMService(
            system_prompt=llm_system_prompt,
            **(llm_config or {})
        )
    
    def run(self) -> Dict[str, Any]:
        """
        Run static analysis on the binary.
        
        Returns:
            Updated state dictionary with findings
        """
        self.logger.info("Starting static analysis of binary")
        
        # Get basic binary info
        binary_info = self.r2.get_binary_info()
        self.logger.debug(f"Binary info: {binary_info}")
        
        # Update architecture info in state
        arch_info = {
            "arch": binary_info.get("bin", {}).get("arch", "unknown"),
            "bits": binary_info.get("bin", {}).get("bits", 0),
            "os": binary_info.get("bin", {}).get("os", "unknown"),
            "type": binary_info.get("bin", {}).get("type", "unknown"),
        }
        security_features = binary_info.get("security", {})
        
        # Perform full analysis
        analysis_results = self.r2.analyze_binary()
        
        # Log key findings
        self.logger.info(f"Architecture: {arch_info['arch']} {arch_info['bits']}-bit")
        self.logger.info(f"Security features: NX={'nx' in security_features}, "
                         f"Canary={'canary' in security_features}, "
                         f"PIE={'pie' in security_features}, "
                         f"RELRO={security_features.get('relro', 'No')}")
        
        # Create reversing report for LLM analysis
        reversing_report = self._create_reversing_report(binary_info, analysis_results)
        
        # Save the raw report to disk
        report_path = self.output_dir / "reversing_report.json"
        with open(report_path, "w") as f:
            json.dump(reversing_report, f, indent=2)
        
        self.logger.info(f"Saved raw reversing report to {report_path}")
        
        # Use LLM to analyze the report
        vulnerability_analysis = self._analyze_vulnerabilities(reversing_report)
        
        # Save the vulnerability analysis to disk
        analysis_path = self.output_dir / "vulnerability_analysis.txt"
        with open(analysis_path, "w") as f:
            f.write(vulnerability_analysis)
        
        self.logger.info(f"Saved vulnerability analysis to {analysis_path}")
        
        # Extract vulnerability info from LLM response
        vulnerabilities = self._extract_vulnerabilities(vulnerability_analysis)
        
        # Update state with findings
        self.update_state({
            "architecture": arch_info,
            "security_features": security_features,
            "vulnerabilities": vulnerabilities,
            "reversing_report": reversing_report,
            "vulnerability_analysis": vulnerability_analysis,
        })
        
        # Log summary of findings
        self.log_result(f"Found {len(vulnerabilities)} potential vulnerabilities")
        for vuln in vulnerabilities:
            self.logger.info(f"Vulnerability: {vuln['type']} at {vuln.get('location', 'unknown')}")
        
        return self.state
    
    def _create_reversing_report(
        self,
        binary_info: Dict[str, Any],
        analysis_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create a comprehensive reversing report for LLM analysis.
        
        Args:
            binary_info: Basic binary information
            analysis_results: Results of full analysis
            
        Returns:
            Structured report dictionary
        """
        return {
            "binary_info": binary_info,
            "functions": analysis_results.get("functions", []),
            "imports": analysis_results.get("imports", []),
            "strings": analysis_results.get("strings", []),
            "vulnerable_functions": analysis_results.get("vulnerable_functions", []),
            "main_disassembly": analysis_results.get("main_disassembly", ""),
            "entry_disassembly": analysis_results.get("entry_disassembly", ""),
        }
    
    def _analyze_vulnerabilities(self, report: Dict[str, Any]) -> str:
        """
        Use LLM to analyze the report for vulnerabilities.
        
        Args:
            report: The reversing report
            
        Returns:
            Vulnerability analysis as text
        """
        # Create a prompt with the most relevant information
        prompt = """
        Please analyze this binary for potential vulnerabilities. Here is the information I have:
        
        ## BINARY INFO
        - Architecture: {arch} {bits}-bit
        - OS: {os}
        - Type: {type}
        
        ## SECURITY FEATURES
        - NX (No-Execute): {nx}
        - Stack Canary: {canary}
        - PIE (Position Independent Executable): {pie}
        - RELRO: {relro}
        
        ## POTENTIALLY VULNERABLE FUNCTION CALLS
        {vulnerable_functions}
        
        ## RELEVANT STRINGS
        {strings}
        
        ## MAIN FUNCTION DISASSEMBLY
        ```
        {main_disassembly}
        ```
        
        Based on this information, identify any potential vulnerabilities in the binary.
        For each vulnerability, specify:
        1. The type of vulnerability
        2. Where it is located (function/address)
        3. How it could be exploited
        4. Any constraints or security mitigations affecting exploitation
        
        Structure your response in a clear, organized format.
        """
        
        # Extract relevant info from the report
        binary_info = report.get("binary_info", {})
        bin_section = binary_info.get("bin", {})
        security = binary_info.get("security", {})
        
        # Format vulnerable functions
        vuln_funcs = report.get("vulnerable_functions", [])
        vuln_funcs_text = "None found\n"
        if vuln_funcs:
            vuln_funcs_text = ""
            for vf in vuln_funcs:
                if vf.get("type") == "imported_vulnerable_function":
                    vuln_funcs_text += f"- Imported: {vf.get('name')} at address {vf.get('address')}\n"
                elif vf.get("type") == "vulnerable_function_call":
                    vuln_funcs_text += f"- Call to {vf.get('function')} at address {vf.get('caller_address')}\n"
        
        # Format strings (only include potentially interesting ones)
        strings = report.get("strings", [])
        interesting_strings = []
        for s in strings:
            string_val = s.get("string", "")
            if any(keyword in string_val.lower() for keyword in 
                   ["password", "user", "admin", "key", "flag", "secret", "buffer", 
                    "overflow", "vuln", "hack", "input", "format"]):
                interesting_strings.append(f"- \"{string_val}\" at {s.get('vaddr')}")
        
        strings_text = "None found\n"
        if interesting_strings:
            strings_text = "\n".join(interesting_strings[:20])  # Limit to 20 strings
            if len(interesting_strings) > 20:
                strings_text += f"\n[...and {len(interesting_strings) - 20} more...]"
        
        # Format the prompt
        formatted_prompt = prompt.format(
            arch=bin_section.get("arch", "unknown"),
            bits=bin_section.get("bits", 0),
            os=bin_section.get("os", "unknown"),
            type=bin_section.get("type", "unknown"),
            nx=security.get("nx", False),
            canary=security.get("canary", False),
            pie=security.get("pie", False),
            relro=security.get("relro", "No"),
            vulnerable_functions=vuln_funcs_text,
            strings=strings_text,
            main_disassembly=report.get("main_disassembly", report.get("entry_disassembly", "No disassembly available"))
        )
        
        # Call LLM
        self.logger.debug("Sending analysis request to LLM")
        response = self.llm.call(formatted_prompt)
        
        return response
    
    def _extract_vulnerabilities(self, analysis: str) -> List[Dict[str, str]]:
        """
        Extract structured vulnerability information from LLM analysis.
        
        This is a best-effort extraction that relies on the LLM formatting
        its response in a somewhat predictable way.
        
        Args:
            analysis: The LLM's vulnerability analysis text
            
        Returns:
            List of vulnerability dictionaries
        """
        # Let's try to extract vulnerabilities based on common patterns
        vulnerabilities = []
        
        # Look for sections that might describe vulnerabilities
        sections = analysis.split("\n\n")
        current_vuln = {}
        
        for section in sections:
            # Look for headers that might indicate a vulnerability section
            section_lower = section.lower()
            
            # Check if this section starts a new vulnerability
            if any(x in section_lower for x in ["vulnerability", "vulnerability type", "vuln #", "issue #"]):
                # Save previous vulnerability if it exists
                if current_vuln and "type" in current_vuln:
                    vulnerabilities.append(current_vuln)
                
                # Start a new vulnerability
                current_vuln = {"description": section}
                
                # Try to extract vulnerability type
                if ":" in section:
                    vuln_type = section.split(":", 1)[1].strip()
                    current_vuln["type"] = vuln_type
                elif "buffer overflow" in section_lower:
                    current_vuln["type"] = "buffer overflow"
                elif "format string" in section_lower:
                    current_vuln["type"] = "format string"
                elif "use after free" in section_lower or "uaf" in section_lower:
                    current_vuln["type"] = "use-after-free"
                elif "integer overflow" in section_lower:
                    current_vuln["type"] = "integer overflow"
                elif "heap" in section_lower:
                    current_vuln["type"] = "heap vulnerability"
            
            # Extract location information
            elif "location" in section_lower or "where" in section_lower:
                current_vuln["location"] = section
                
                # Try to extract function name or address
                if "function" in section_lower and ":" in section:
                    func = section.split(":", 1)[1].strip()
                    current_vuln["function"] = func
                
                if "address" in section_lower and ":" in section:
                    addr = section.split(":", 1)[1].strip()
                    current_vuln["address"] = addr
            
            # Extract exploitation info
            elif "exploit" in section_lower or "how" in section_lower:
                current_vuln["exploitation"] = section
            
            # Extract constraints
            elif "constraint" in section_lower or "mitigation" in section_lower:
                current_vuln["constraints"] = section
        
        # Don't forget the last vulnerability
        if current_vuln and "type" in current_vuln:
            vulnerabilities.append(current_vuln)
        
        # If we couldn't extract structured vulnerabilities, try a simpler approach
        if not vulnerabilities:
            # Look for keyword patterns
            for vuln_type in ["buffer overflow", "format string", "use-after-free", 
                              "integer overflow", "heap overflow", "stack overflow"]:
                if vuln_type in analysis.lower():
                    # Find the paragraph containing this vulnerability
                    for para in sections:
                        if vuln_type in para.lower():
                            vulnerabilities.append({
                                "type": vuln_type,
                                "description": para,
                            })
        
        return vulnerabilities 