"""
Service for interacting with language models.
"""

import json
import logging
import os
import yaml
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import openai
from openai import OpenAI
from pwnai.utils.logger import setup_logger


class LLMService:
    """
    Service for interacting with language models via OpenAI's API or compatible alternatives.
    
    This class handles the communication with LLM providers and manages
    the context and prompt formatting.
    """
    
    def __init__(
        self,
        model_config: Optional[str] = None,
        system_prompt: Optional[str] = None,
        config_path: Optional[str] = "/opt/models.yaml",
    ):
        """
        Initialize the LLM service.
        
        Args:
            model_config: The model configuration to use (e.g., "openai", "ollama")
                          If None, the default from config will be used
            system_prompt: System prompt to use for all conversations
            config_path: Path to the model configuration YAML file
        """
        self.logger = setup_logger(name="pwnai.LLMService")
        
        # Load configuration
        self.config = self._load_config(config_path)
        if not self.config:
            self.logger.error("Failed to load model configuration. Using OpenAI defaults.")
            self.config = {
                "openai": {
                    "url": "https://api.openai.com/v1",
                    "model": "gpt-4",
                    "temperature": 0.7,
                    "max_tokens": 4096,
                }
            }
        
        # Determine which model configuration to use
        if model_config:
            if model_config in self.config:
                self.model_config = self.config[model_config]
                self.provider = model_config
            else:
                self.logger.warning(f"Model configuration '{model_config}' not found. Using default.")
                self.model_config, self.provider = self._get_default_config()
        else:
            self.model_config, self.provider = self._get_default_config()
        
        # Set model parameters
        self.model = self.model_config.get("model", "gpt-4")
        self.temperature = self.model_config.get("temperature", 0.7)
        self.max_tokens = self.model_config.get("max_tokens", 4096)
        self.url = self.model_config.get("url")
        
        # Use provided API key or get from environment
        self.api_key = self.model_config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        if not self.api_key and self.provider == "openai":
            self.logger.warning("No OpenAI API key provided. LLM calls will fail.")
        
        # Initialize the client if using OpenAI
        self.client = None
        if self.provider == "openai":
            self.client = OpenAI(api_key=self.api_key)
        
        # Set system prompt
        system_prompt_prefix = self.model_config.get("system_prompt_prefix", "")
        self.system_prompt = system_prompt or (
            system_prompt_prefix + " " +
            "Analyze the information provided and respond with detailed, technical insights. "
            "Focus on identifying vulnerabilities and exploitation techniques. "
            "Be specific and provide concrete steps when suggesting exploits."
        )
        
        self.conversation_history: List[Dict[str, str]] = [
            {"role": "system", "content": self.system_prompt}
        ]
        
        self.logger.info(f"Initialized LLM service with provider: {self.provider}, model: {self.model}")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load the model configuration from a YAML file."""
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            self.logger.error(f"Error loading model configuration: {str(e)}")
            return {}
    
    def _get_default_config(self) -> tuple:
        """Get the default model configuration from the config file."""
        # First, look for a configuration with default: true
        for provider, config in self.config.items():
            if config.get("default", False):
                return config, provider
        
        # If no default is specified, use OpenAI if it exists
        if "openai" in self.config:
            return self.config["openai"], "openai"
        
        # Otherwise, use the first configuration found
        if self.config:
            provider = next(iter(self.config))
            return self.config[provider], provider
        
        # Fallback to empty config
        return {}, "openai"
    
    def call(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        with_history: bool = True,
    ) -> str:
        """
        Call the LLM with a prompt.
        
        Args:
            prompt: The prompt to send to the LLM
            temperature: Override the default temperature
            max_tokens: Override the default max_tokens
            model: Override the default model
            system_prompt: Override the default system prompt
            with_history: Whether to include conversation history
            
        Returns:
            The LLM's response text
        """
        # Use provided values or defaults
        _temperature = temperature if temperature is not None else self.temperature
        _max_tokens = max_tokens if max_tokens is not None else self.max_tokens
        _model = model if model is not None else self.model
        
        # Create messages list
        if with_history:
            messages = list(self.conversation_history)
            if system_prompt:
                # Replace system prompt for this call only
                messages[0] = {"role": "system", "content": system_prompt}
        else:
            # Start fresh conversation with just the system prompt
            _sys_prompt = system_prompt or self.system_prompt
            messages = [{"role": "system", "content": _sys_prompt}]
        
        # Add the new user prompt
        messages.append({"role": "user", "content": prompt})
        
        self.logger.debug(f"Calling {_model} with {len(messages)} messages")
        
        try:
            # Call the appropriate provider
            if self.provider == "openai":
                return self._call_openai(messages, _model, _temperature, _max_tokens, with_history)
            else:
                return self._call_compatible_api(messages, _model, _temperature, _max_tokens, with_history)
        
        except Exception as e:
            self.logger.error(f"Error calling LLM: {str(e)}")
            return f"Error: {str(e)}"
    
    def _call_openai(
        self,
        messages: List[Dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
        with_history: bool
    ) -> str:
        """Call the OpenAI API directly."""
        response = self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        
        response_text = response.choices[0].message.content
        
        # Update conversation history if using history
        if with_history:
            self.conversation_history.append({"role": "user", "content": messages[-1]["content"]})
            self.conversation_history.append({"role": "assistant", "content": response_text})
        
        return response_text
    
    def _call_compatible_api(
        self,
        messages: List[Dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
        with_history: bool
    ) -> str:
        """Call a compatible API (like Ollama) using the OpenAI-compatible format."""
        # Determine if we're using a large model (by name)
        large_model = any(hint in model.lower() for hint in ["32b", "65b", "70b", "qwq"])
        
        # For large models, set a longer timeout
        timeout = 300 if large_model else 120  # 5 minutes for large models
        
        # For large models, we'll create a simpler prompt to reduce generation time
        if large_model:
            self.logger.info(f"Using large model mode for {model} with timeout {timeout}s")
            
            # Simplify the prompt by concatenating messages into a single prompt string
            prompt_text = "System: " + messages[0]["content"] + "\n\n"
            
            # Add previous conversation messages (excluding the most recent user message)
            for msg in messages[1:-1]:
                role = "Assistant" if msg["role"] == "assistant" else "User"
                prompt_text += f"{role}: {msg['content']}\n\n"
            
            # Add the most recent user message
            prompt_text += "User: " + messages[-1]["content"] + "\n\nAssistant: "
            
            # Update payload for large model optimization
            payload = {
                "model": model,
                "prompt": prompt_text,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False
            }
            self.logger.debug(f"Using completion endpoint for large model {model}")
            api_url = self.url.replace("/chat", "/generate") if "/chat" in self.url else self.url
        else:
            # Standard chat format for normal-sized models
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False  # Explicitly disable streaming for compatibility
            }
            api_url = self.url
        
        self.logger.debug(f"Sending request to {api_url} with model {model}")
        
        try:
            response = requests.post(
                api_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout
            )
            
            if response.status_code != 200:
                error_msg = f"API call failed with status code {response.status_code}: {response.text}"
                self.logger.error(error_msg)
                return f"Error: {error_msg}"
            
            # Try to parse the response according to the expected format
            try:
                response_data = response.json()
                
                # Extract response text from different formats
                response_text = None
                
                # Handle Ollama-specific format (most common case)
                if "message" in response_data and "content" in response_data["message"]:
                    response_text = response_data["message"]["content"]
                # Handle Ollama completion API format
                elif "response" in response_data:
                    response_text = response_data["response"]
                # Handle OpenAI-compatible format
                elif "choices" in response_data and len(response_data["choices"]) > 0:
                    if "message" in response_data["choices"][0]:
                        response_text = response_data["choices"][0]["message"]["content"]
                    elif "text" in response_data["choices"][0]:
                        response_text = response_data["choices"][0]["text"]
                
                # If response_text is still None, try to extract it from the response data
                if response_text is None:
                    self.logger.warning(f"Unknown response format: {str(response_data)[:200]}...")
                    
                    # Try a direct approach based on the structure
                    if isinstance(response_data, dict):
                        # For Ollama format
                        if "message" in response_data:
                            message = response_data["message"]
                            if isinstance(message, dict) and "content" in message:
                                response_text = message["content"]
                        
                        # For any other format
                        for key in ["content", "text", "response", "result", "output"]:
                            if key in response_data:
                                response_text = response_data[key]
                                break
                
                # If still no content found, use the whole response as string
                if response_text is None:
                    response_text = str(response_data)
                    
                # Update conversation history if using history
                if with_history:
                    self.conversation_history.append({"role": "user", "content": messages[-1]["content"]})
                    self.conversation_history.append({"role": "assistant", "content": response_text})
                
                return response_text
                
            except json.JSONDecodeError as e:
                # Handle streaming or malformed responses
                self.logger.warning(f"JSON decode error: {str(e)}. Attempting alternative parsing.")
                
                # Try to parse as multiple JSON objects (common in streaming responses)
                try:
                    # Get the raw text and try to extract the last complete JSON object
                    raw_text = response.text
                    # Look for the last occurrence of a valid JSON object
                    response_text = ""
                    
                    # Simple approach: try to find the content in the raw text
                    import re
                    
                    # Try to find Ollama-style content
                    content_match = re.search(r'"content"\s*:\s*"(.*?)(?:"\s*}|"\s*,)', raw_text)
                    if content_match:
                        response_text = content_match.group(1)
                        # Unescape any escaped quotes
                        response_text = response_text.replace('\\"', '"')
                    else:
                        # Try to find any other response format
                        for pattern in [
                            r'"response"\s*:\s*"(.*?)(?:"\s*}|"\s*,)',
                            r'"text"\s*:\s*"(.*?)(?:"\s*}|"\s*,)',
                            r'"output"\s*:\s*"(.*?)(?:"\s*}|"\s*,)'
                        ]:
                            match = re.search(pattern, raw_text)
                            if match:
                                response_text = match.group(1)
                                # Unescape any escaped quotes
                                response_text = response_text.replace('\\"', '"')
                                break
                                
                        if not response_text:
                            # If no match found, return the raw text (truncated if too long)
                            max_chars = 2000
                            response_text = f"Failed to extract response properly. Raw response (truncated): {raw_text[:max_chars]}"
                            if len(raw_text) > max_chars:
                                response_text += "..."
                    
                    # Update conversation history if using history
                    if with_history:
                        self.conversation_history.append({"role": "user", "content": messages[-1]["content"]})
                        self.conversation_history.append({"role": "assistant", "content": response_text})
                    
                    return response_text
                    
                except Exception as e2:
                    error_msg = f"Failed to parse API response after retry: {str(e2)}. Response: {response.text[:300]}..."
                    self.logger.error(error_msg)
                    return f"Error: {error_msg}"
                
        except requests.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            self.logger.error(error_msg)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            return f"Error: {error_msg}"
    
    def reset_conversation(self) -> None:
        """Reset the conversation history, keeping only the system prompt."""
        self.conversation_history = [self.conversation_history[0]]
        self.logger.debug("Conversation history reset")
    
    def update_system_prompt(self, system_prompt: str) -> None:
        """
        Update the system prompt for future conversations.
        
        Args:
            system_prompt: The new system prompt
        """
        self.system_prompt = system_prompt
        self.conversation_history[0] = {"role": "system", "content": system_prompt}
        self.logger.debug("System prompt updated") 