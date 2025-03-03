# Tool Integration Guide

This guide explains how to add new tool integrations to the MCP framework.

## Overview

MCP's plugin-based architecture makes it easy to add support for new security tools. Each tool integration is implemented as a plugin that:

1. Executes the tool with appropriate parameters
2. Parses the tool's output into standardized events
3. Publishes these events to the message broker

## Integration Process

### Step 1: Create a New Plugin Class

Create a new Python file for your tool in the appropriate category directory:

```python
# tools/your_category/your_tool_plugin.py

from tools.base_plugin import BasePlugin

class YourToolPlugin(BasePlugin):
    """
    Plugin for integrating YourTool.
    """
    
    def __init__(self, message_broker):
        """Initialize the YourTool plugin."""
        super().__init__(message_broker, "YourTool")
        self.binary_path = self._find_binary()
    
    def _find_binary(self) -> str:
        """Find the YourTool binary in the system."""
        return "yourtool"  # Or use which/where command to locate it
    
    def get_capabilities(self) -> List[str]:
        """Return the capabilities of YourTool."""
        return [
            "capability_one", 
            "capability_two"
        ]
    
    def execute_task(self, task_parameters: Dict) -> Dict:
        """Execute a YourTool task with the given parameters."""
        # Implement execution logic here
        pass
    
    def parse_output(self, output_data: Union[str, bytes]) -> List[Dict]:
        """Parse YourTool output into standardized events."""
        # Implement parsing logic here
        pass
```

### Step 2: Implement the execute_task Method

This method is responsible for running the tool with the appropriate parameters:

```python
def execute_task(self, task_parameters: Dict) -> Dict:
    """
    Execute a YourTool task with the given parameters.
    
    Args:
        task_parameters: Dictionary containing parameters for the task
            Required: parameters specific to your tool
            
    Returns:
        Dict: Result information including tool output
    """
    # Validate required parameters
    if 'required_param' not in task_parameters:
        raise ValueError("Missing required parameter: required_param")
    
    # Extract parameters
    required_param = task_parameters['required_param']
    optional_param = task_parameters.get('optional_param', 'default_value')
    
    # Build the command
    command = [self.binary_path]
    
    # Add parameters to command
    command.extend(['--param', required_param])
    
    if optional_param:
        command.extend(['--optional', optional_param])
    
    # Run the command
    return_code, stdout, stderr = self.run_command(command)
    
    result = {
        'return_code': return_code,
        'success': return_code == 0,
        'stdout': stdout,
        'stderr': stderr
    }
    
    # If successful, parse the output
    if result['success']:
        try:
            events = self.parse_output(stdout)
            
            # Publish events to message broker
            self.publish_events(events, task_parameters.get('engagement_id'))
            
            result['event_count'] = len(events)
            result['scan_time'] = datetime.now().isoformat()
        except Exception as e:
            self.logger.error(f"Error parsing YourTool output: {str(e)}")
            result['error'] = str(e)
            result['success'] = False
    
    return result
```

### Step 3: Implement the parse_output Method

This method transforms the tool's output into standardized events:

```python
def parse_output(self, output_data: Union[str, bytes]) -> List[Dict]:
    """
    Parse YourTool output into standardized events.
    
    Args:
        output_data: YourTool output as string or bytes
        
    Returns:
        List[Dict]: List of events generated from the output
    """
    events = []
    
    try:
        # Convert bytes to string if needed
        if isinstance(output_data, bytes):
            output_data = output_data.decode('utf-8')
        
        # Parse the output (example logic)
        for line in output_data.splitlines():
            # Look for patterns in the output
            if "Finding:" in line:
                # Extract information
                finding = line.split("Finding:")[1].strip()
                
                # Create an event
                event = {
                    "event_type": "YourToolFinding",
                    "finding": finding,
                    "timestamp": datetime.now().isoformat()
                }
                events.append(event)
        
        return events
    
    except Exception as e:
        self.logger.error(f"Error parsing YourTool output: {str(e)}")
        return []
```

### Step 4: Register the Plugin in the Factory

Add your plugin to the plugin factory to make it available to the system:

```python
# tools/plugin_factory.py

from tools.your_category.your_tool_plugin import YourToolPlugin

class PluginFactory:
    """Factory for creating tool plugins."""
    
    @staticmethod
    def create_plugin(tool_name: str, message_broker) -> BasePlugin:
        """
        Create a tool plugin instance.
        
        Args:
            tool_name: Name of the tool
            message_broker: Message broker connection
            
        Returns:
            BasePlugin: Plugin instance
        """
        if tool_name.lower() == "yourtool":
            return YourToolPlugin(message_broker)
        # ... other tools ...
        else:
            raise ValueError(f"Unsupported tool: {tool_name}")
```

### Step 5: Add Tool-Specific Event Handlers

In the Context Engine, add handlers for any new event types produced by your tool:

```python
# core/context_engine.py

# Add to the event_handlers dictionary in __init__
self.event_handlers = {
    # Existing handlers...
    "YourToolFinding": self._handle_your_tool_finding,
}

def _handle_your_tool_finding(self, event_data: Dict):
    """Handle YourTool finding event."""
    # Process and store the finding
    # ...
```

### Step 6: Add Tests

Create unit tests for your plugin:

```python
# tests/tools/your_category/test_your_tool_plugin.py

import unittest
from unittest.mock import MagicMock
from tools.your_category.your_tool_plugin import YourToolPlugin

class TestYourToolPlugin(unittest.TestCase):
    
    def setUp(self):
        self.mock_broker = MagicMock()
        self.plugin = YourToolPlugin(self.mock_broker)
    
    def test_parse_output_valid(self):
        # Arrange
        sample_output = "Some output\nFinding: Test vulnerability\nMore output"
        
        # Act
        events = self.plugin.parse_output(sample_output)
        
        # Assert
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "YourToolFinding")
        self.assertEqual(events[0]["finding"], "Test vulnerability")
```

### Step 7: Update Documentation

Update the README.md and other documentation to include your new tool integration.

## Event Type Guidelines

When creating events, follow these guidelines:

1. Use descriptive event types: `"HostDiscovered"`, `"VulnerabilityFound"`, etc.
2. Include all relevant information in the event
3. Use consistent field names across similar events
4. Use ISO format for timestamps
5. Include source information (`"source_tool"` is added automatically)

Common event types include:

- `"HostDiscovered"`: A new host was found
- `"PortFound"`: An open port was found
- `"ServiceDetected"`: A service was identified on a port
- `"VulnerabilityFound"`: A vulnerability was discovered
- `"CredentialFound"`: A set of credentials was found

## Example Events

Here are examples of standard event formats:

```json
{
  "event_type": "HostDiscovered",
  "ip": "192.168.1.10",
  "hostname": "webserver.example.com",
  "timestamp": "2023-04-16T10:05:22Z"
}

{
  "event_type": "VulnerabilityFound",
  "ip": "192.168.1.10",
  "port": 80,
  "vulnerability": "CVE-2021-44228",
  "description": "Log4j Remote Code Execution",
  "severity": "critical",
  "timestamp": "2023-04-16T10:05:22Z"
}
```

## Best Practices

1. **Error Handling**: Always include robust error handling in your plugin
2. **Resource Management**: Clean up temporary files and processes
3. **Logging**: Use the plugin's logger for detailed logging
4. **Documentation**: Document all parameters and behavior of your plugin
5. **Sanitization**: Be careful with user-supplied input to commands

## Troubleshooting

If you encounter issues:

1. Test the tool manually to verify its behavior
2. Enable debug logging to see detailed information
3. Check for differences in tool output format across versions
4. Verify that the message broker is receiving events
5. Check the Context Engine logs for processing errors

Feel free to ask for help in issues or discussions if you get stuck!
