"""
Base Plugin Interface

This module defines the base class for all tool integration plugins.
All tool plugins should inherit from this class and implement its methods.
"""

import abc
import json
import logging
import subprocess
import tempfile
import os
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class BasePlugin(abc.ABC):
    """
    Abstract base class for all tool integration plugins.
    """
    
    def __init__(self, message_broker, tool_name: str):
        """
        Initialize the plugin with a message broker connection.
        
        Args:
            message_broker: Connection to the message queue
            tool_name: Name of the tool this plugin integrates with
        """
        self.broker = message_broker
        self.tool_name = tool_name
        self.logger = logging.getLogger(f"plugin.{tool_name}")
        self.logger.info(f"{tool_name} plugin initialized")
    
    @abc.abstractmethod
    def execute_task(self, task_parameters: Dict) -> Dict:
        """
        Execute a task using the tool.
        
        Args:
            task_parameters: Dictionary containing parameters for the task
            
        Returns:
            Dict: Result information
        """
        pass
    
    @abc.abstractmethod
    def parse_output(self, output_data: Union[str, bytes, Dict]) -> List[Dict]:
        """
        Parse the output of the tool into a list of standardized events.
        
        Args:
            output_data: Output from the tool (could be file content, stdout, etc.)
            
        Returns:
            List[Dict]: List of events generated from the tool output
        """
        pass
    
    def run_command(self, command: List[str], timeout: int = 3600) -> Tuple[int, str, str]:
        """
        Run a shell command and return its output.
        
        Args:
            command: Command to run as a list of arguments
            timeout: Maximum time to wait for the command to complete (in seconds)
            
        Returns:
            Tuple[int, str, str]: Return code, stdout, stderr
        """
        self.logger.info(f"Running command: {' '.join(command)}")
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
            
            self.logger.debug(f"Command completed with return code {return_code}")
            
            return return_code, stdout, stderr
        
        except subprocess.TimeoutExpired:
            process.kill()
            self.logger.error(f"Command timed out after {timeout} seconds")
            return 124, "", "Command timed out"
        
        except Exception as e:
            self.logger.error(f"Error running command: {str(e)}")
            return 1, "", str(e)
    
    def run_command_with_output_file(self, command: List[str], output_format: str = "xml") -> Tuple[int, str]:
        """
        Run a command that outputs to a file and return the file path.
        
        Args:
            command: Command to run as a list of arguments
            output_format: Format of the output file (xml, json, etc.)
            
        Returns:
            Tuple[int, str]: Return code and path to the output file
        """
        # Create a temporary directory for output
        temp_dir = tempfile.mkdtemp(prefix="mcp_")
        output_file = os.path.join(temp_dir, f"output.{output_format}")
        
        # Add the output file parameter to the command
        if self.tool_name.lower() == "nmap":
            if output_format == "xml":
                command.extend(["-oX", output_file])
            elif output_format == "json":
                command.extend(["-oJ", output_file])
        else:
            # Generic output redirection for other tools
            command.extend(["-o", output_file])
        
        # Run the command
        return_code, stdout, stderr = self.run_command(command)
        
        # Check if the output file was created
        if return_code == 0 and os.path.exists(output_file):
            return return_code, output_file
        else:
            self.logger.error(f"Output file not created: {stderr}")
            return return_code, ""
    
    def publish_events(self, events: List[Dict], engagement_id: str = None):
        """
        Publish events to the message broker.
        
        Args:
            events: List of event dictionaries to publish
            engagement_id: ID of the current engagement (if known)
        """
        for event in events:
            # Add common fields to event
            event["source_tool"] = self.tool_name
            event["timestamp"] = event.get("timestamp", datetime.now().isoformat())
            event["event_id"] = str(uuid.uuid4())
            
            if engagement_id:
                event["engagement_id"] = engagement_id
            
            # Publish the event
            self.broker.publish("tool_events", event)
            self.logger.debug(f"Published event: {event['event_type']}")
    
    def register_with_context_engine(self):
        """
        Register this plugin with the context engine.
        This allows the engine to know which tools are available.
        """
        registration_info = {
            "event_type": "ToolRegistration",
            "tool_name": self.tool_name,
            "capabilities": self.get_capabilities(),
            "timestamp": datetime.now().isoformat()
        }
        
        self.broker.publish("tool_registrations", registration_info)
        self.logger.info(f"Registered {self.tool_name} plugin with capabilities: {self.get_capabilities()}")
    
    def get_capabilities(self) -> List[str]:
        """
        Get the capabilities of this tool.
        
        Returns:
            List[str]: List of capability strings
        """
        # To be overridden by subclasses
        return ["generic_tool"]
