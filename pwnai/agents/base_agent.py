"""
Base agent class for all PwnAI agents.
"""

import abc
import logging
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
    ):
        """
        Initialize the base agent.
        
        Args:
            state: Shared state dictionary for inter-agent communication
            binary_path: Path to the target binary
            output_dir: Directory to store output files
            llm_config: Configuration for the LLM (model, temperature, etc.)
        """
        self.state = state
        self.binary_path = binary_path
        self.output_dir = output_dir
        self.llm_config = llm_config or {}
        
        # Set up logger
        self.logger = setup_logger(
            name=f"pwnai.{self.__class__.__name__}",
        )
        
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