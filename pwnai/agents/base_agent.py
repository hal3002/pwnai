"""
Base agent class for all PwnAI agents.
"""

import abc
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pwnai.utils.logger import setup_logger


class BaseAgent(abc.ABC):
    """
    Base class for all PwnAI agents.
    
    This abstract class defines the common interface and functionality
    that all specialized agents should implement.
    """
    
    def __init__(
        self,
        state: Dict[str, Any],
        binary_path: Path,
        output_dir: Path,
        llm_config: Optional[Dict[str, Any]] = None,
        llm_service: Optional[Any] = None,
    ):
        """
        Initialize the base agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM (model, temperature, etc.)
            llm_service: Optional shared LLM service instance
        """
        self.state = state
        self.binary_path = binary_path
        self.output_dir = output_dir
        self.llm_config = llm_config or {}
        self.llm_service = llm_service
        
        # Get a logger for this agent class (reusing existing logger if already configured)
        agent_name = self.__class__.__name__
        logger_name = f"pwnai.{agent_name}"
        self.logger = logging.getLogger(logger_name)
        
        # Ensure binary exists
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")
    
    @abc.abstractmethod
    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Run the agent's main task.
        
        Each agent implementation must override this method to perform
        its specific task in the exploitation workflow.
        
        Returns:
            Updated state dictionary with the agent's findings
        """
        pass
    
    def update_state(self, updates: Dict[str, Any]) -> None:
        """
        Update the shared state with new information.
        
        Args:
            updates: Dictionary containing state updates
        """
        self.logger.debug(f"Updating state with {len(updates)} keys")
        self.state.update(updates)
    
    def get_from_state(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the shared state.
        
        Args:
            key: The key to look up
            default: Default value if key doesn't exist
            
        Returns:
            The value from the state or the default
        """
        return self.state.get(key, default)
    
    def get_state_value(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the shared state (alias for get_from_state).
        
        Args:
            key: The key to look up
            default: Default value if key doesn't exist
            
        Returns:
            The value from the state or the default
        """
        return self.get_from_state(key, default)
    
    def _call_llm(self, prompt: str, **kwargs) -> str:
        """
        Call the LLM with a prompt.
        
        This method should be implemented by a subclass or overridden
        to use the specific LLM API (e.g., OpenAI, Anthropic, etc.).
        
        Args:
            prompt: The prompt to send to the LLM
            **kwargs: Additional parameters to pass to the LLM API
            
        Returns:
            The LLM's response
        """
        # This is a placeholder that would be replaced with actual implementation
        # that interfaces with the LLM provider
        self.logger.warning("_call_llm not fully implemented in the base class")
        return f"LLM response to: {prompt[:50]}..."
    
    def log_result(self, message: str) -> None:
        """
        Log an important result from the agent.
        
        Args:
            message: The message to log
        """
        self.logger.info(f"Result: {message}")
    
    @staticmethod
    def format_prompt(template: str, **kwargs) -> str:
        """
        Format a prompt template with provided variables.
        
        Args:
            template: The prompt template with placeholders
            **kwargs: Variables to insert into the template
            
        Returns:
            The formatted prompt
        """
        return template.format(**kwargs)
    
    def get_user_feedback(self) -> Optional[str]:
        """
        Get user feedback from the state.
        
        Returns:
            User feedback string or None if not provided
        """
        return self.state.get("user_feedback")
        
    def get_source_file(self) -> Optional[str]:
        """
        Get path to the source file from the state.
        
        Returns:
            Source file path or None if not provided
        """
        return self.state.get("source_file")
    
    def read_source_file(self) -> Optional[str]:
        """
        Read the contents of the source file if available.
        
        Returns:
            Source file contents as string or None if not available
        """
        source_file = self.get_source_file()
        if not source_file:
            return None
            
        try:
            source_path = Path(source_file)
            if not source_path.exists():
                self.logger.warning(f"Source file not found: {source_file}")
                return None
                
            with open(source_path, 'r') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading source file: {str(e)}")
            return None
        
    def incorporate_feedback(self, prompt: str) -> str:
        """
        Incorporate user feedback into a prompt if available.
        
        Args:
            prompt: The original prompt
            
        Returns:
            Modified prompt with user feedback if available
        """
        feedback = self.get_user_feedback()
        if not feedback:
            return prompt
            
        # Add feedback to the prompt
        feedback_section = f"\n\nUSER FEEDBACK:\n{feedback}\n\nPlease take this feedback into account in your analysis and recommendations."
        
        return prompt + feedback_section
        
    def incorporate_source(self, prompt: str) -> str:
        """
        Incorporate source file contents into a prompt if available.
        
        Args:
            prompt: The original prompt
            
        Returns:
            Modified prompt with source code if available
        """
        source_code = self.read_source_file()
        if not source_code:
            return prompt
            
        # Add source code to the prompt
        source_section = f"\n\nSOURCE CODE:\n```\n{source_code}\n```\n\nPlease analyze the source code to identify vulnerabilities and provide more precise exploitation techniques."
        
        return prompt + source_section
        
    def incorporate_vulnerability_feedback(self, prompt: str, vulnerability: Dict[str, Any]) -> str:
        """
        Incorporate vulnerability-specific feedback into a prompt if available.
        
        Args:
            prompt: The original prompt
            vulnerability: Vulnerability dictionary which may contain user_feedback
            
        Returns:
            Modified prompt with vulnerability-specific feedback if available
        """
        if not vulnerability or "user_feedback" not in vulnerability:
            return prompt
            
        # Add vulnerability-specific feedback to the prompt
        feedback = vulnerability["user_feedback"]
        feedback_section = f"\n\nVULNERABILITY-SPECIFIC FEEDBACK:\n{feedback}\n\nPlease focus on this feedback when analyzing this specific vulnerability."
        
        return prompt + feedback_section 