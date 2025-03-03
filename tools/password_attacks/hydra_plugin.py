"""
Hydra Integration Plugin

This module integrates Hydra password cracking functionality into the MCP system.
Hydra is a fast network login cracker for various protocols (SSH, FTP, HTTP, etc.).
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple

from tools.base_plugin import BasePlugin

class HydraPlugin(BasePlugin):
    """
    Plugin for integrating Hydra password cracking tool.
    """
    
    def __init__(self, message_broker):
        """Initialize the Hydra plugin."""
        super().__init__(message_broker, "Hydra")
        self.binary_path = self._find_binary()
    
    def _find_binary(self) -> str:
        """
        Find the Hydra binary in the system.
        
        Returns:
            str: Path to the Hydra binary
        """
        # In a container environment, Hydra will typically be in the PATH
        return "hydra"
    
    def get_capabilities(self) -> List[str]:
        """
        Get the capabilities of Hydra.
        
        Returns:
            List[str]: List of capability strings
        """
        return [
            "password_cracking", 
            "brute_force", 
            "credential_testing",
            "online_password_attack"
        ]
    
    def execute_task(self, task_parameters: Dict) -> Dict:
        """
        Execute a Hydra password cracking task.
        
        Args:
            task_parameters: Dictionary containing parameters for the task
                Required: 'target_host' - Host to attack
                Required: 'protocol' - Protocol to attack (ssh, ftp, http-get, etc.)
                Optional: 'port' - Port number
                Optional: 'userlist' - Path to list of usernames
                Optional: 'passlist' - Path to list of passwords
                Optional: 'username' - Single username (alternative to userlist)
                Optional: 'password' - Single password (alternative to passlist)
                Optional: 'options' - Additional Hydra options
                Optional: 'timeout' - Scan timeout in seconds
                Optional: 'max_attempts' - Maximum attempts per service (default: 1)
                
        Returns:
            Dict: Result information including cracked credentials
        """
        # Validate required parameters
        if 'target_host' not in task_parameters:
            raise ValueError("Missing required parameter: target_host")
        
        if 'protocol' not in task_parameters:
            raise ValueError("Missing required parameter: protocol")
        
        target_host = task_parameters['target_host']
        protocol = task_parameters['protocol']
        port = task_parameters.get('port', '')
        timeout = task_parameters.get('timeout', 3600)  # Default 1 hour timeout
        max_attempts = task_parameters.get('max_attempts', 1)
        
        # Build the command
        command = [self.binary_path]
        
        # Add verbosity
        command.append("-V")
        
        # Add max tasks
        command.extend(["-t", str(max_attempts)])
        
        # Add JSON output if supported (newer Hydra versions)
        try:
            # Check if the installed Hydra supports JSON output
            check_cmd = [self.binary_path, "-h"]
            _, stdout, _ = self.run_command(check_cmd)
            
            if "-o" in stdout and "json" in stdout:
                # JSON output is supported
                command.extend(["-o", "hydra_output.json", "-b", "json"])
                json_output = True
            else:
                # Fall back to standard output
                json_output = False
        except Exception:
            # Fall back to standard output if we can't determine
            json_output = False
        
        # Add port if specified
        if port:
            command.extend(["-s", str(port)])
        
        # Add user/pass specifications
        if 'username' in task_parameters:
            # Single username
            command.extend(["-l", task_parameters['username']])
        elif 'userlist' in task_parameters:
            # Username list
            command.extend(["-L", task_parameters['userlist']])
        else:
            raise ValueError("Either 'username' or 'userlist' must be provided")
        
        if 'password' in task_parameters:
            # Single password
            command.extend(["-p", task_parameters['password']])
        elif 'passlist' in task_parameters:
            # Password list
            command.extend(["-P", task_parameters['passlist']])
        else:
            raise ValueError("Either 'password' or 'passlist' must be provided")
        
        # Add any custom options
        if 'options' in task_parameters:
            options = task_parameters['options']
            if isinstance(options, list):
                command.extend(options)
            else:
                command.append(options)
        
        # Add protocol-specific options if needed
        if protocol == "http-post-form" or protocol == "http-get-form":
            if 'form_path' not in task_parameters:
                raise ValueError(f"'form_path' is required for {protocol}")
            
            form_path = task_parameters['form_path']
            form_data = task_parameters.get('form_data', "")
            failure_string = task_parameters.get('failure_string', "")
            
            # Format: /login.php:user=^USER^&pass=^PASS^:F=incorrect
            protocol_option = f"{form_path}:{form_data}:{failure_string}"
            command.append(protocol_option)
        
        # Add target and protocol
        command.append(target_host)
        command.append(protocol)
        
        # Run the command
        return_code, stdout, stderr = self.run_command(command, timeout)
        
        result = {
            'return_code': return_code,
            'success': return_code == 0,
            'stdout': stdout,
            'stderr': stderr
        }
        
        # If successful, parse the output
        if result['success']:
            try:
                if json_output and os.path.exists("hydra_output.json"):
                    with open("hydra_output.json", 'r') as f:
                        file_content = f.read()
                    
                    # Parse the file content
                    events = self.parse_json_output(file_content, target_host, protocol)
                else:
                    # Parse stdout
                    events = self.parse_output(stdout, target_host, protocol)
                
                # Publish events to message broker
                self.publish_events(events, task_parameters.get('engagement_id'))
                
                result['event_count'] = len(events)
                result['credentials_found'] = len(events)
                result['scan_time'] = datetime.now().isoformat()
            except Exception as e:
                self.logger.error(f"Error parsing Hydra output: {str(e)}")
                result['error'] = str(e)
                result['success'] = False
        
        return result
    
    def parse_output(self, output_data: Union[str, bytes], target_host: str, protocol: str) -> List[Dict]:
        """
        Parse Hydra standard output into standardized events.
        
        Args:
            output_data: Hydra output as string or bytes
            target_host: The target host that was scanned
            protocol: The protocol that was tested
            
        Returns:
            List[Dict]: List of events generated from the Hydra output
        """
        events = []
        
        try:
            # Convert bytes to string if needed
            if isinstance(output_data, bytes):
                output_data = output_data.decode('utf-8')
            
            # Pattern to match successful login attempts
            # Example: [80][http-post-form] host: 10.0.0.1   login: admin   password: password123
            pattern = r"\[\d+\]\[[\w-]+\] host: ([^ ]+)\s+login: ([^ ]+)\s+password: (.*)"
            
            for line in output_data.splitlines():
                match = re.search(pattern, line)
                if match:
                    host = match.group(1)
                    username = match.group(2)
                    password = match.group(3).strip()
                    
                    cred_event = {
                        "event_type": "CredentialFound",
                        "ip": host,
                        "service": protocol,
                        "username": username,
                        "password_plaintext": password,
                        "source": "hydra",
                        "is_validated": True,
                        "timestamp": datetime.now().isoformat()
                    }
                    events.append(cred_event)
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error parsing Hydra output: {str(e)}")
            return []
    
    def parse_json_output(self, json_str: str, target_host: str, protocol: str) -> List[Dict]:
        """
        Parse Hydra JSON output into standardized events.
        
        Args:
            json_str: Hydra JSON output as string
            target_host: The target host that was scanned
            protocol: The protocol that was tested
            
        Returns:
            List[Dict]: List of events generated from the Hydra output
        """
        events = []
        
        try:
            data = json.loads(json_str)
            
            if "results" in data:
                for result in data["results"]:
                    if "password" in result and "login" in result:
                        host = result.get("host", target_host)
                        port = result.get("port", "")
                        username = result.get("login", "")
                        password = result.get("password", "")
                        
                        cred_event = {
                            "event_type": "CredentialFound",
                            "ip": host,
                            "port": port,
                            "service": protocol,
                            "username": username,
                            "password_plaintext": password,
                            "source": "hydra",
                            "is_validated": True,
                            "timestamp": datetime.now().isoformat()
                        }
                        events.append(cred_event)
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error parsing Hydra JSON output: {str(e)}")
            return []
