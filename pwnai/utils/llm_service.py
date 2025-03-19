"""
Service for interacting with language models.
"""

import json
import logging
import os
import yaml
import requests
import time
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import openai
from openai import OpenAI
from pwnai.utils.logger import setup_logger

# Dictionary to store existing LLM service instances by config
_llm_service_cache = {}

class LLMService:
    """
    Service for interacting with language models via OpenAI's API or compatible alternatives.
    
    This class handles the communication with LLM providers and manages
    the context and prompt formatting.
    """
    
    def __new__(
        cls,
        model_config: Optional[str] = None,
        system_prompt: Optional[str] = None,
        config_path: Optional[str] = None,
        agent_type: Optional[str] = None,
    ):
        """
        Create or reuse an LLMService instance based on the configuration.
        
        This implements a singleton-like pattern, where we reuse instances
        with the same model_config.
        """
        # Create a cache key based on the configuration
        cache_key = f"{model_config}:{config_path}:{agent_type}"
        
        # If we already have an instance with this configuration, return it
        if cache_key in _llm_service_cache:
            return _llm_service_cache[cache_key]
        
        # Otherwise, create a new instance
        instance = super().__new__(cls)
        _llm_service_cache[cache_key] = instance
        return instance
    
    def __init__(
        self,
        model_config: Optional[str] = None,
        system_prompt: Optional[str] = None,
        config_path: Optional[str] = None,
        agent_type: Optional[str] = None,
    ):
        """
        Initialize the LLM service.
        
        Args:
            model_config: The model provider to use (e.g., "openai", "claude")
                          If None, the default from config will be used
            system_prompt: System prompt to use for all conversations
            config_path: Path to the configuration YAML file
            agent_type: Type of agent (e.g., "reversing", "debugging") to use specific configuration
        """
        # Check if this instance has already been initialized
        if hasattr(self, 'initialized') and self.initialized:
            return
            
        self.logger = setup_logger(name="pwnai.LLMService")
        self.agent_type = agent_type  # Store agent_type for reference

        # If config_path is provided, use it directly without searching
        if config_path and os.path.exists(config_path):
            self.logger.debug(f"Using provided config path: {config_path}")
            # Expand user path for home directory reference (~)
            if config_path.startswith("~"):
                config_path = os.path.expanduser(config_path)
        else:
            # If config_path is not provided or doesn't exist, look in standard locations
            config_path = self._find_config_path()
            if not config_path:
                self.logger.warning("No configuration file found, using default settings")
        
        # Load configuration
        self.config = self._load_config(config_path)
        providers_config = self.config.get("providers", {})
        agents_config = self.config.get("agents", {})
        
        if not providers_config:
            self.logger.error("Failed to load provider configurations. Using OpenAI defaults.")
            providers_config = {
                "openai": {
                    "url": "https://api.openai.com/v1",
                }
            }
        
        # First check if we should use agent-specific configuration
        if agent_type and agent_type in agents_config:
            # Get the agent-specific configuration
            agent_config = agents_config[agent_type]
            self.logger.info(f"Using agent-specific configuration for {agent_type}")
            
            # Get the provider specified for this agent
            provider_name = agent_config.get("provider")
            
            if not provider_name:
                self.logger.warning(f"No provider specified for agent {agent_type}, using agent config directly")
                self.model_config = agent_config
                self.provider = "unknown"
            elif provider_name not in providers_config:
                self.logger.warning(f"Provider '{provider_name}' not found, using agent config directly")
                self.model_config = agent_config
                self.provider = provider_name
            else:
                # Start with the provider's config (for URL, API settings)
                self.model_config = providers_config[provider_name].copy()
                # Add the agent-specific settings (model, temperature, etc.)
                self.model_config.update(agent_config)
                self.provider = provider_name
                
            self.logger.debug(f"Using provider '{self.provider}' for agent '{agent_type}'")
            
        # Otherwise, use model_config if provided (provider name)
        elif model_config:
            if model_config in providers_config:
                # If a model_config is given but it's only a provider name, we need to look for defaults
                self.provider = model_config
                
                # Start with the provider config
                self.model_config = providers_config[model_config].copy()
                
                # Check if we have a default agent config to use for the model, temperature, etc.
                if "default" in agents_config:
                    default_config = agents_config["default"]
                    # Only use the default if it has the same provider
                    if default_config.get("provider") == model_config:
                        self.model_config.update(default_config)
                    else:
                        self.logger.warning(f"Default agent uses different provider '{default_config.get('provider')}', not applying its settings")
                else:
                    self.logger.warning(f"No default agent configuration found, model settings may be incomplete")
            else:
                self.logger.warning(f"Provider configuration '{model_config}' not found. Using default agent.")
                self.model_config, self.provider = self._get_default_agent_config()
        else:
            # Fall back to default agent config
            self.model_config, self.provider = self._get_default_agent_config()
        
        # Set model parameters - ensure they exist
        self.model = self.model_config.get("model")
        if not self.model:
            self.logger.warning(f"No model specified for provider {self.provider}, this may cause errors")
            
        self.temperature = self.model_config.get("temperature", 0.7)
        self.max_tokens = self.model_config.get("max_tokens", 4096)
        self.url = self.model_config.get("url")
        
        # Use provided API key or get from environment
        self.api_key = self.model_config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        if not self.api_key and self.provider == "openai":
            self.logger.warning("No OpenAI API key provided. LLM calls will fail.")
            
        # Set Anthropic API key if using Claude
        self.anthropic_api_key = self.model_config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not self.anthropic_api_key and self.provider == "claude":
            self.logger.warning("No Anthropic API key provided. LLM calls will fail.")
            # Try to get from ANTHROPIC_API_KEY environment variable
            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not self.anthropic_api_key:
                self.logger.error("ANTHROPIC_API_KEY environment variable not set. Claude calls will fail.")
        
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
        
        if agent_type:
            self.logger.info(f"Initialized LLM service for {agent_type} agent with provider: {self.provider}, model: {self.model}")
        else:
            self.logger.info(f"Initialized LLM service with provider: {self.provider}, model: {self.model}")
        
        # Mark this instance as initialized to avoid re-initialization
        self.initialized = True
    
    def _find_config_path(self) -> str:
        """Find the config.yml configuration file."""
        # Check current directory
        if os.path.exists("config.yml"):
            return "config.yml"
        
        # Check home directory ~/.pwnai/config.yml
        home_config = os.path.expanduser("~/.pwnai/config.yml")
        if os.path.exists(home_config):
            return home_config
        
        # Check for legacy models.yaml (for backward compatibility)
        if os.path.exists("models.yaml"):
            return "models.yaml"
        
        # Check home directory ~/.pwnai/models.yaml (for backward compatibility)
        home_legacy_config = os.path.expanduser("~/.pwnai/models.yaml")
        if os.path.exists(home_legacy_config):
            return home_legacy_config
        
        # Check package directory
        package_config = os.path.join(os.path.dirname(__file__), "../config.yml")
        if os.path.exists(package_config):
            return package_config
        
        package_legacy_config = os.path.join(os.path.dirname(__file__), "../models.yaml")
        if os.path.exists(package_legacy_config):
            return package_legacy_config
        
        # Default to /opt as fallback
        if os.path.exists("/opt/config.yml"):
            return "/opt/config.yml"
        return "/opt/models.yaml"
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load the configuration from a YAML file."""
        try:
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file)
                
                # Handle the new config.yml format with 'providers' section
                if "providers" in config:
                    self.logger.debug("Found 'providers' section in config, using new format")
                    return {"providers": config["providers"], "agents": config.get("agents", {})}
                
                # Handle legacy models.yaml format (backward compatibility)
                self.logger.debug("No 'providers' section found, assuming legacy format")
                return {"providers": config, "agents": {}}
                
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            return {"providers": {}, "agents": {}}
    
    def _get_default_agent_config(self) -> tuple:
        """Get the default agent configuration from the config file."""
        agents_config = self.config.get("agents", {})
        
        # First, check for an agent with the name "default"
        if "default" in agents_config:
            default_config = agents_config["default"]
            provider = default_config.get("provider", "unknown")
            
            # If the default agent specifies a provider, merge provider settings
            if provider in self.config.get("providers", {}):
                # Start with provider settings
                merged_config = self.config["providers"][provider].copy()
                # Override with agent settings
                merged_config.update(default_config)
                return merged_config, provider
            else:
                # Just use the default agent config as is
                return default_config, provider
        
        # Next, look for an agent config with default: true
        for agent_name, agent_config in agents_config.items():
            if agent_config.get("default", False):
                provider = agent_config.get("provider", "unknown")
                
                # If the agent specifies a provider, merge provider settings
                if provider in self.config.get("providers", {}):
                    # Start with provider settings
                    merged_config = self.config["providers"][provider].copy()
                    # Override with agent settings
                    merged_config.update(agent_config)
                    return merged_config, provider
                else:
                    # Just use the agent config as is
                    return agent_config, provider
        
        # Fallback to empty config with warning
        self.logger.error("No default agent configuration found, this will likely cause errors")
        return {}, "unknown"
    
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
            elif self.provider == "claude":
                return self._call_anthropic(messages, _model, _temperature, _max_tokens, with_history)
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
    
    def _call_anthropic(
        self,
        messages: List[Dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
        with_history: bool
    ) -> str:
        """Call the Anthropic API with Claude-specific formatting."""
        if not self.anthropic_api_key:
            error_msg = "No Anthropic API key available. Please set ANTHROPIC_API_KEY environment variable."
            self.logger.error(error_msg)
            return f"Error: {error_msg}"
            
        # Set API headers according to Anthropic's documentation
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": self.anthropic_api_key,
            "anthropic-version": "2023-06-01"
        }
        
        self.logger.debug(f"Using API key: {self.anthropic_api_key[:4]}...{self.anthropic_api_key[-4:] if self.anthropic_api_key else 'None'}")
        
        # Extract system message from the messages array
        system_content = None
        filtered_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                # Anthropic only accepts 'user' and 'assistant' roles
                filtered_messages.append(msg)
        
        # Anthropic API payload format with system as top-level parameter
        payload = {
            "model": model,
            "messages": filtered_messages,
            "system": system_content,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        # Log the exact payload for debugging
        self.logger.debug(f"Anthropic payload: {json.dumps(payload)[:500]}...")
        
        # Implement retry logic with exponential backoff
        max_retries = 5
        base_delay = 2  # Start with 2 second delay
        
        for retry in range(max_retries + 1):
            try:
                self.logger.debug(f"Sending request to Anthropic API with model {model}, attempt {retry+1}/{max_retries+1}")
                
                response = requests.post(
                    self.url,
                    json=payload,
                    headers=headers,
                    timeout=120
                )
                
                # Handle successful response
                if response.status_code == 200:
                    response_data = response.json()
                    
                    # Extract response from Anthropic format
                    if "content" in response_data and len(response_data["content"]) > 0:
                        # Handle new Anthropic API format with content array
                        content_parts = [part["text"] for part in response_data["content"] if part["type"] == "text"]
                        response_text = "".join(content_parts)
                    else:
                        # Fallback for older API or unexpected format
                        response_text = response_data.get("content", str(response_data))
                    
                    # Update conversation history if using history
                    if with_history:
                        self.conversation_history.append({"role": "user", "content": messages[-1]["content"]})
                        self.conversation_history.append({"role": "assistant", "content": response_text})
                    
                    return response_text
                
                # Handle overloaded errors (529) with retry logic
                elif response.status_code == 529:
                    error_data = response.json()
                    error_msg = f"API overloaded (attempt {retry+1}/{max_retries+1}): {error_data}"
                    self.logger.warning(error_msg)
                    
                    if retry < max_retries:
                        # Calculate delay with exponential backoff and jitter
                        delay = base_delay * (2 ** retry) + random.uniform(0, 1)
                        self.logger.info(f"Retrying in {delay:.2f} seconds...")
                        time.sleep(delay)
                        continue
                    else:
                        # Last retry failed
                        self.logger.error(f"Max retries exceeded for Anthropic API call")
                        return f"Error: Anthropic API overloaded. Max retries exceeded."
                
                # Handle other errors
                else:
                    error_msg = f"API call failed with status code {response.status_code}: {response.text}"
                    self.logger.error(error_msg)
                    return f"Error: {error_msg}"
                    
            except requests.RequestException as e:
                error_msg = f"Request failed: {str(e)}"
                self.logger.error(error_msg)
                
                if retry < max_retries:
                    # Calculate delay with exponential backoff and jitter
                    delay = base_delay * (2 ** retry) + random.uniform(0, 1)
                    self.logger.info(f"Retrying in {delay:.2f} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    return f"Error: {error_msg}"
            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                self.logger.error(error_msg)
                return f"Error: {error_msg}"
        
        # Should not reach here, but just in case
        return "Error: Failed to get response from Anthropic API after retries."
    
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