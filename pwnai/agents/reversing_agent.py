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
from pwnai.utils.logger import setup_logger


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
        llm_service: Optional[LLMService] = None,
    ):
        """
        Initialize the Reversing Agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM
            llm_service: Optional shared LLM service instance
        """
        super().__init__(state, binary_path, output_dir, llm_config, llm_service)
        
        # Initialize Radare2 wrapper
        self.r2 = Radare2(binary_path)
        
        # Initialize LLM service if not provided
        if self.llm_service is None:
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
        else:
            self.llm = self.llm_service
        
        # Set up logging
        self.logger = setup_logger(name=f"pwnai.{self.__class__.__name__}")
    
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
        self.logger.info(f"Security features: NX={security_features.get('nx', False)}, "
                         f"Canary={security_features.get('canary', False)}, "
                         f"PIE={security_features.get('pie', False)}, "
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
        
        # Consolidate similar vulnerabilities to reduce redundancy
        vulnerabilities = self._consolidate_vulnerabilities(vulnerabilities)
        
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
                    called_func = vf.get('function', 'unknown')
                    caller_addr = vf.get('caller_address', 'unknown')
                    vuln_funcs_text += f"- Call to {called_func} at address {caller_addr}\n"
                    
                    # Also add detailed information to help LLM understand
                    if vf.get('instruction'):
                        vuln_funcs_text += f"  Instruction: {vf.get('instruction')}\n"
                    if vf.get('disassembly'):
                        vuln_funcs_text += f"  Context:\n"
                        for line in vf.get('disassembly', '').split('\n')[:5]:  # First 5 lines of context
                            vuln_funcs_text += f"    {line}\n"
        
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
        
        # Incorporate user feedback if available
        formatted_prompt = self.incorporate_feedback(formatted_prompt)
        
        # Incorporate source file if available
        formatted_prompt = self.incorporate_source(formatted_prompt)
        
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
    
    def _consolidate_vulnerabilities(self, vulnerabilities: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Consolidate similar vulnerabilities to reduce redundancy.
        
        This method groups vulnerabilities by type and location, merging those
        that are likely referring to the same underlying issue.
        
        Args:
            vulnerabilities: List of extracted vulnerabilities
            
        Returns:
            Consolidated list of vulnerabilities
        """
        if not vulnerabilities:
            return []
            
        self.logger.info(f"Consolidating {len(vulnerabilities)} vulnerabilities")
        
        # Group vulnerabilities by type
        grouped_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown").lower()
            if vuln_type not in grouped_by_type:
                grouped_by_type[vuln_type] = []
            grouped_by_type[vuln_type].append(vuln)
        
        consolidated = []
        
        for vuln_type, vulns in grouped_by_type.items():
            # If only one vulnerability of this type, add it as is
            if len(vulns) == 1:
                consolidated.append(vulns[0])
                continue
                
            # Group by location/function
            by_location = {}
            for vuln in vulns:
                # Create a location key based on function or address
                location_key = "unknown"
                if "function" in vuln:
                    location_key = vuln["function"]
                elif "address" in vuln:
                    location_key = vuln["address"]
                elif "location" in vuln:
                    # Try to extract function/address from location string
                    location = vuln["location"].lower()
                    if "function" in location and ":" in location:
                        location_key = location.split(":", 1)[1].strip()
                    elif "address" in location and ":" in location:
                        location_key = location.split(":", 1)[1].strip()
                    else:
                        location_key = location[:50]  # Use part of location as key
                
                if location_key not in by_location:
                    by_location[location_key] = []
                by_location[location_key].append(vuln)
            
            # For each location, merge vulnerabilities
            for location, loc_vulns in by_location.items():
                if len(loc_vulns) == 1:
                    consolidated.append(loc_vulns[0])
                else:
                    # Merge multiple vulnerabilities at same location
                    merged = self._merge_vulnerabilities(loc_vulns)
                    consolidated.append(merged)
        
        # Sort consolidated vulnerabilities by type for consistency
        consolidated.sort(key=lambda x: x.get("type", "").lower())
        
        self.logger.info(f"Consolidated down to {len(consolidated)} unique vulnerabilities")
        return consolidated
    
    def _merge_vulnerabilities(self, vulns: List[Dict[str, str]]) -> Dict[str, str]:
        """
        Merge multiple vulnerability dictionaries into one comprehensive entry.
        
        Args:
            vulns: List of vulnerability dictionaries to merge
            
        Returns:
            Merged vulnerability dictionary
        """
        if not vulns:
            return {}
        if len(vulns) == 1:
            return vulns[0]
            
        # Start with the most detailed vulnerability as base
        # (the one with the most fields)
        base = max(vulns, key=lambda x: len(x))
        merged = base.copy()
        
        # Create a combined description
        descriptions = []
        for vuln in vulns:
            if "description" in vuln and vuln["description"] not in descriptions:
                descriptions.append(vuln["description"])
        
        if descriptions:
            merged["description"] = "\n\n".join(descriptions)
            
        # Combine exploitation information
        exploitation_info = []
        for vuln in vulns:
            if "exploitation" in vuln and vuln["exploitation"] not in exploitation_info:
                exploitation_info.append(vuln["exploitation"])
        
        if exploitation_info:
            merged["exploitation"] = "\n\n".join(exploitation_info)
            
        # Combine constraint information
        constraint_info = []
        for vuln in vulns:
            if "constraints" in vuln and vuln["constraints"] not in constraint_info:
                constraint_info.append(vuln["constraints"])
                
        if constraint_info:
            merged["constraints"] = "\n\n".join(constraint_info)
            
        # Generate a consolidated type if needed
        if "type" not in merged or merged["type"].lower() == "unknown":
            # Extract type from the first vulnerability that has one
            for vuln in vulns:
                if "type" in vuln and vuln["type"].lower() != "unknown":
                    merged["type"] = vuln["type"]
                    break
        
        return merged 