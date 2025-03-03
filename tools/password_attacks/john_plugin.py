"""
John the Ripper Integration Plugin

This module integrates John the Ripper password cracking functionality into the MCP system.
John is used for offline password hash cracking.
"""

import os
import re
import tempfile
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Tuple

from tools.base_plugin import BasePlugin

class JohnPlugin(BasePlugin):
    """
    Plugin for integrating John the Ripper password cracking tool.
    """
    
    def __init__(self, message_broker):
        """Initialize the John plugin."""
        super().__init__(message_broker, "JohnTheRipper")
        self.binary_path = self._find_binary()
    
    def _find_binary(self) -> str:
        """
        Find the John binary in the system.
        
        Returns:
            str: Path to the John binary
        """
        # In a container environment, John will typically be in the PATH
        return "john"
    
    def get_capabilities(self) -> List[str]:
        """
        Get the capabilities of John the Ripper.
        
        Returns:
            List[str]: List of capability strings
        """
        return [
            "password_cracking", 
            "offline_hash_cracking", 
            "hash_identification"
        ]
    
    def execute_task(self, task_parameters: Dict) -> Dict:
        """
        Execute a John the Ripper password cracking task.
        
        Args:
            task_parameters: Dictionary containing parameters for the task
                Required: Either 'hash_file' (path to file with hashes) or 'hash_string' (single hash string)
                Optional: 'hash_format' - Format of the hash (e.g., 'md5', 'sha1', 'ntlm')
                Optional: 'wordlist' - Path to wordlist file
                Optional: 'rules' - Rule set to use
                Optional: 'incremental' - Use incremental mode
                Optional: 'max_runtime' - Maximum runtime in seconds
                Optional: 'options' - Additional John options
                Optional: 'timeout' - Task timeout in seconds
                
        Returns:
            Dict: Result information including cracked passwords
        """
        # Validate parameters - need either hash file or hash string
        if 'hash_file' not in task_parameters and 'hash_string' not in task_parameters:
            raise ValueError("Either 'hash_file' or 'hash_string' must be provided")
        
        # If hash_string is provided, write it to a temporary file
        hash_file = task_parameters.get('hash_file')
        if not hash_file and 'hash_string' in task_parameters:
            fd, hash_file = tempfile.mkstemp(prefix="john_hash_")
            with os.fdopen(fd, 'w') as f:
                f.write(task_parameters['hash_string'])
        
        hash_format = task_parameters.get('hash_format', '')
        wordlist = task_parameters.get('wordlist', '')
        rules = task_parameters.get('rules', '')
        incremental = task_parameters.get('incremental', False)
        max_runtime = task_parameters.get('max_runtime', 0)
        timeout = task_parameters.get('timeout', 3600)  # Default 1 hour timeout
        
        # Build the command
        command = [self.binary_path]
        
        # Add hash format if specified
        if hash_format:
            command.extend(["--format=" + hash_format])
        
        # Add wordlist if specified
        if wordlist:
            command.extend(["--wordlist=" + wordlist])
        
        # Add rules if specified
        if rules:
            command.extend(["--rules=" + rules])
        
        # Add incremental mode if enabled
        if incremental:
            if isinstance(incremental, str):
                command.extend(["--incremental=" + incremental])
            else:
                command.extend(["--incremental"])
        
        # Add max runtime if specified
        if max_runtime > 0:
            command.extend(["--max-run-time=" + str(max_runtime)])
        
        # Add any custom options
        if 'options' in task_parameters:
            options = task_parameters['options']
            if isinstance(options, list):
                command.extend(options)
            else:
                command.append(options)
        
        # Add hash file
        command.append(hash_file)
        
        # Run the command
        return_code, stdout, stderr = self.run_command(command, timeout)
        
        result = {
            'return_code': return_code,
            'success': return_code == 0,
            'stdout': stdout,
            'stderr': stderr
        }
        
        # Even if John times out, it may have cracked some passwords
        # So we continue with the show command to see what was cracked
        
        # Run John's --show option to display cracked passwords
        show_command = [self.binary_path, "--show", hash_file]
        if hash_format:
            show_command.extend(["--format=" + hash_format])
        
        _, show_stdout, _ = self.run_command(show_command)
        
        # Parse the output to extract cracked passwords
        try:
            events = self.parse_output(show_stdout, hash_file)
            
            # Publish events to message broker
            self.publish_events(events, task_parameters.get('engagement_id'))
            
            result['event_count'] = len(events)
            result['passwords_cracked'] = len(events)
            result['scan_time'] = datetime.now().isoformat()
        except Exception as e:
            self.logger.error(f"Error parsing John output: {str(e)}")
            result['error'] = str(e)
        
        # Clean up temporary file if we created one
        if 'hash_string' in task_parameters and hash_file:
            try:
                os.unlink(hash_file)
            except Exception as e:
                self.logger.warning(f"Failed to delete temporary hash file: {str(e)}")
        
        return result
    
    def parse_output(self, output_data: Union[str, bytes], hash_file: str) -> List[Dict]:
        """
        Parse John the Ripper output into standardized events.
        
        Args:
            output_data: John output as string or bytes
            hash_file: Path to the hash file that was cracked
            
        Returns:
            List[Dict]: List of events generated from the John output
        """
        events = []
        
        try:
            # Convert bytes to string if needed
            if isinstance(output_data, bytes):
                output_data = output_data.decode('utf-8')
            
            # When running john --show, the output format is:
            # username:password:additional:fields:from:original:hash:file
            
            for line in output_data.splitlines():
                if ':' in line and not line.startswith("0 password hashes cracked"):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password = parts[1]
                        
                        # Try to determine hash type from additional fields
                        hash_type = self._determine_hash_type(parts[2:] if len(parts) > 2 else [], hash_file)
                        
                        # Create password cracked event
                        password_event = {
                            "event_type": "PasswordCracked",
                            "username": username,
                            "password_plaintext": password,
                            "hash_type": hash_type,
                            "source": "john",
                            "timestamp": datetime.now().isoformat()
                        }
                        events.append(password_event)
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error parsing John output: {str(e)}")
            return []
    
    def _determine_hash_type(self, hash_parts: List[str], hash_file: str) -> str:
        """
        Try to determine the hash type from additional fields.
        
        Args:
            hash_parts: Additional fields from the John output
            hash_file: Path to the hash file
            
        Returns:
            str: Hash type if determined, otherwise empty string
        """
        # Check if hash file has a specific format (e.g., .ntlm, .md5, etc.)
        if hash_file:
            extension = os.path.splitext(hash_file)[1].lower()
            if extension:
                # Remove the leading dot
                return extension[1:]
        
        # Try to determine from the hash format itself
        # This is a simplified version - in a real implementation, you'd check more specific patterns
        if len(hash_parts) > 0:
            if len(hash_parts[0]) == 32:
                return "md5"
            elif len(hash_parts[0]) == 40:
                return "sha1"
            elif len(hash_parts[0]) == 64:
                return "sha256"
            elif "LM" in ''.join(hash_parts):
                return "lm"
            elif "NTLM" in ''.join(hash_parts):
                return "ntlm"
        
        # Default - unknown
        return "unknown"
    
    def identify_hash_type(self, hash_string: str) -> List[str]:
        """
        Use John's hash identification functionality to identify hash types.
        
        Args:
            hash_string: The hash string to identify
            
        Returns:
            List[str]: Possible hash types
        """
        # Write hash to temporary file
        fd, hash_file = tempfile.mkstemp(prefix="john_identify_")
        with os.fdopen(fd, 'w') as f:
            f.write(hash_string)
        
        # Run John with --identify option
        command = [self.binary_path, "--identify", hash_file]
        _, stdout, _ = self.run_command(command)
        
        # Clean up temporary file
        try:
            os.unlink(hash_file)
        except Exception:
            pass
        
        # Parse the output to extract identified hash types
        possible_types = []
        
        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8')
        
        for line in stdout.splitlines():
            if 'hash type' in line.lower():
                match = re.search(r'hash type: (\w+)', line, re.IGNORECASE)
                if match:
                    possible_types.append(match.group(1))
        
        return possible_types
