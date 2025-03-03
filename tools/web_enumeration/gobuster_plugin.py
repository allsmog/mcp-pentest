"""
Gobuster Integration Plugin

This module integrates Gobuster directory brute-force functionality into the MCP system.
It handles executing Gobuster scans and parsing their outputs into standardized events.
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple

from tools.base_plugin import BasePlugin

class GobusterPlugin(BasePlugin):
    """
    Plugin for integrating Gobuster web directory brute-force tool.
    """
    
    def __init__(self, message_broker):
        """Initialize the Gobuster plugin."""
        super().__init__(message_broker, "Gobuster")
        self.binary_path = self._find_binary()
    
    def _find_binary(self) -> str:
        """
        Find the Gobuster binary in the system.
        
        Returns:
            str: Path to the Gobuster binary
        """
        # In a container environment, Gobuster will typically be in the PATH
        return "gobuster"
    
    def get_capabilities(self) -> List[str]:
        """
        Get the capabilities of Gobuster.
        
        Returns:
            List[str]: List of capability strings
        """
        return [
            "directory_brute_force", 
            "web_path_discovery", 
            "vhost_discovery",
            "dns_subdomain_brute_force"
        ]
    
    def execute_task(self, task_parameters: Dict) -> Dict:
        """
        Execute a Gobuster scan with the given parameters.
        
        Args:
            task_parameters: Dictionary containing parameters for the scan
                Required: 'target_url' - URL to scan
                Required: 'mode' - Scan mode (dir, dns, vhost, etc)
                Optional: 'wordlist' - Path to wordlist file (default: uses a standard wordlist)
                Optional: 'extensions' - File extensions to search
                Optional: 'threads' - Number of concurrent threads
                Optional: 'options' - Additional Gobuster options
                Optional: 'timeout' - Scan timeout in seconds
                
        Returns:
            Dict: Result information including scan output
        """
        # Validate required parameters
        if 'target_url' not in task_parameters:
            raise ValueError("Missing required parameter: target_url")
        
        if 'mode' not in task_parameters:
            raise ValueError("Missing required parameter: mode")
        
        target_url = task_parameters['target_url']
        mode = task_parameters['mode']
        wordlist = task_parameters.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        extensions = task_parameters.get('extensions', '')
        threads = task_parameters.get('threads', 10)
        timeout = task_parameters.get('timeout', 3600)  # Default 1 hour timeout
        
        # Build the command
        command = [self.binary_path, mode]
        
        # Add URL specification
        command.extend(['-u', target_url])
        
        # Add wordlist
        command.extend(['-w', wordlist])
        
        # Add extensions if provided
        if extensions:
            command.extend(['-x', extensions])
        
        # Add threads
        command.extend(['-t', str(threads)])
        
        # Add output format (json if supported by the installed version)
        try:
            # Check if the installed Gobuster supports JSON output
            check_cmd = [self.binary_path, "--help"]
            _, stdout, _ = self.run_command(check_cmd)
            
            if "-o" in stdout and "json" in stdout:
                # JSON output is supported
                command.extend(['-o', 'output.json', '--output-format', 'json'])
                json_output = True
            else:
                # Fall back to text output
                command.extend(['-o', 'output.txt'])
                json_output = False
        except Exception:
            # Fall back to text output if we can't determine
            command.extend(['-o', 'output.txt'])
            json_output = False
        
        # Add quiet mode to reduce noise
        command.append('-q')
        
        # Add any custom options
        if 'options' in task_parameters:
            options = task_parameters['options']
            if isinstance(options, list):
                command.extend(options)
            else:
                command.append(options)
        
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
                # Determine where the output file was written
                output_file = 'output.json' if json_output else 'output.txt'
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        file_content = f.read()
                    
                    # Parse the file content
                    events = self.parse_output(file_content, is_json=json_output, target_url=target_url)
                else:
                    # Fall back to parsing stdout
                    events = self.parse_output(stdout, is_json=False, target_url=target_url)
                
                # Publish events to message broker
                self.publish_events(events, task_parameters.get('engagement_id'))
                
                result['event_count'] = len(events)
                result['scan_time'] = datetime.now().isoformat()
            except Exception as e:
                self.logger.error(f"Error parsing Gobuster output: {str(e)}")
                result['error'] = str(e)
                result['success'] = False
        
        return result
    
    def parse_output(self, output_data: Union[str, bytes], is_json: bool = False, target_url: str = "") -> List[Dict]:
        """
        Parse Gobuster output into standardized events.
        
        Args:
            output_data: Gobuster output as string or bytes
            is_json: Whether the output is in JSON format
            target_url: The target URL that was scanned
            
        Returns:
            List[Dict]: List of events generated from the Gobuster output
        """
        events = []
        
        try:
            # Convert bytes to string if needed
            if isinstance(output_data, bytes):
                output_data = output_data.decode('utf-8')
            
            # Parse based on format
            if is_json:
                events = self._parse_json_output(output_data, target_url)
            else:
                events = self._parse_text_output(output_data, target_url)
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error parsing Gobuster output: {str(e)}")
            return []
    
    def _parse_json_output(self, json_str: str, target_url: str) -> List[Dict]:
        """
        Parse Gobuster JSON output.
        
        Args:
            json_str: JSON output string
            target_url: The target URL that was scanned
            
        Returns:
            List[Dict]: List of events
        """
        events = []
        
        try:
            data = json.loads(json_str)
            
            # Process results
            if 'results' in data:
                for result in data['results']:
                    path = result.get('path', '')
                    status = result.get('status', 0)
                    size = result.get('size', 0)
                    
                    # Only process successful results (status 200, 204, 301, 302, etc.)
                    if status >= 200 and status < 400:
                        full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
                        
                        # Create web resource event
                        resource_event = {
                            "event_type": "WebResourceDiscovered",
                            "url": full_url,
                            "path": path,
                            "status_code": status,
                            "size": size,
                            "timestamp": datetime.now().isoformat()
                        }
                        events.append(resource_event)
        
        except Exception as e:
            self.logger.error(f"Error parsing Gobuster JSON: {str(e)}")
        
        return events
    
    def _parse_text_output(self, text: str, target_url: str) -> List[Dict]:
        """
        Parse Gobuster text output.
        
        Args:
            text: Text output string
            target_url: The target URL that was scanned
            
        Returns:
            List[Dict]: List of events
        """
        events = []
        
        # Regex pattern to match Gobuster output lines
        # Example: /admin (Status: 301) [Size: 169]
        pattern = r"(/[^\s]*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]"
        
        for line in text.splitlines():
            match = re.search(pattern, line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))
                
                # Only process successful results (status 200, 204, 301, 302, etc.)
                if status >= 200 and status < 400:
                    full_url = f"{target_url.rstrip('/')}{path}"
                    
                    # Create web resource event
                    resource_event = {
                        "event_type": "WebResourceDiscovered",
                        "url": full_url,
                        "path": path,
                        "status_code": status,
                        "size": size,
                        "timestamp": datetime.now().isoformat()
                    }
                    events.append(resource_event)
        
        return events