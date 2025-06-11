#!/usr/bin/env python3
"""
MCP Pentest Server

This is the main MCP server that provides penetration testing tools
through the Model Context Protocol interface.
"""

import asyncio
import json
import logging
from typing import Any, Sequence
from pathlib import Path
import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)
import mcp.types as types

# Import tool plugins
from tools.network_scanners.nmap_plugin import NmapPlugin
from tools.web_enumeration.gobuster_plugin import GobusterPlugin

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-pentest-server")

class MockMessageBroker:
    """Simple message broker for the MCP server"""
    def __init__(self):
        self.events = []
    
    def publish(self, topic: str, message: dict):
        """Publish a message to a topic"""
        self.events.append({
            'topic': topic,
            'message': message,
            'timestamp': message.get('timestamp')
        })
        logger.info(f"Published to {topic}: {message.get('event_type', 'Unknown')}")

# Initialize the server
server = Server("mcp-pentest")

# Initialize message broker and plugins
message_broker = MockMessageBroker()
nmap_plugin = NmapPlugin(message_broker)
gobuster_plugin = GobusterPlugin(message_broker)

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available penetration testing tools"""
    return [
        Tool(
            name="nmap_scan",
            description="Execute Nmap network scans for port discovery, service detection, and OS fingerprinting",
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "string",
                        "description": "Target hosts/networks to scan (e.g., '192.168.1.0/24', '10.0.0.1', 'example.com')"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["basic", "service", "os", "full", "aggressive", "quick"],
                        "description": "Type of scan to perform",
                        "default": "basic"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Ports to scan (e.g., '80,443', '1-1000', 'top-ports 1000')",
                        "default": ""
                    },
                    "options": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional Nmap command line options",
                        "default": []
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 3600
                    }
                },
                "required": ["targets"]
            }
        ),
        Tool(
            name="gobuster_scan",
            description="Execute Gobuster directory/file brute-force scans for web application enumeration",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Target URL to scan (e.g., 'https://example.com')"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["dir", "dns", "vhost"],
                        "description": "Gobuster scan mode",
                        "default": "dir"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file",
                        "default": "/usr/share/wordlists/dirb/common.txt"
                    },
                    "extensions": {
                        "type": "string",
                        "description": "File extensions to search for (e.g., 'php,html,txt')",
                        "default": ""
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 10
                    },
                    "options": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional Gobuster command line options",
                        "default": []
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 3600
                    }
                },
                "required": ["target_url", "mode"]
            }
        ),
        Tool(
            name="get_scan_events",
            description="Retrieve events from completed scans",
            inputSchema={
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (optional)",
                        "default": ""
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return",
                        "default": 100
                    }
                },
                "required": []
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Handle tool execution requests"""
    
    if name == "nmap_scan":
        try:
            # Execute nmap scan
            result = nmap_plugin.execute_task(arguments)
            
            if result.get('success'):
                response = f"✅ Nmap scan completed successfully!\n\n"
                response += f"📊 **Scan Results:**\n"
                response += f"- Return code: {result.get('return_code', 'N/A')}\n"
                response += f"- Events generated: {result.get('event_count', 0)}\n"
                response += f"- Scan time: {result.get('scan_time', 'N/A')}\n"
                
                if result.get('output_file'):
                    response += f"- Output file: {result.get('output_file')}\n"
                
                # Add summary of events found
                recent_events = [e for e in message_broker.events if e['topic'] == 'tool_events'][-10:]
                if recent_events:
                    response += f"\n🎯 **Recent Events:**\n"
                    for event in recent_events:
                        msg = event['message']
                        event_type = msg.get('event_type', 'Unknown')
                        if event_type == 'HostDiscovered':
                            response += f"- 🖥️  Host discovered: {msg.get('ip')} ({msg.get('hostname', 'no hostname')})\n"
                        elif event_type == 'PortFound':
                            response += f"- 🔌 Port found: {msg.get('ip')}:{msg.get('port')}/{msg.get('protocol')}\n"
                        elif event_type == 'ServiceDetected':
                            response += f"- 🔍 Service detected: {msg.get('service')} on {msg.get('ip')}:{msg.get('port')}\n"
                        elif event_type == 'VulnerabilityFound':
                            response += f"- ⚠️  Vulnerability: {msg.get('vulnerability')} on {msg.get('ip')}:{msg.get('port')}\n"
                        else:
                            response += f"- ℹ️  {event_type}: {msg.get('ip', 'N/A')}\n"
            else:
                response = f"❌ Nmap scan failed!\n\n"
                response += f"- Return code: {result.get('return_code', 'N/A')}\n"
                if result.get('error'):
                    response += f"- Error: {result.get('error')}\n"
                if result.get('stderr'):
                    response += f"- stderr: {result.get('stderr')}\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Error executing nmap scan: {e}")
            return [types.TextContent(type="text", text=f"❌ Error executing nmap scan: {str(e)}")]
    
    elif name == "gobuster_scan":
        try:
            # Execute gobuster scan
            result = gobuster_plugin.execute_task(arguments)
            
            if result.get('success'):
                response = f"✅ Gobuster scan completed successfully!\n\n"
                response += f"📊 **Scan Results:**\n"
                response += f"- Return code: {result.get('return_code', 'N/A')}\n"
                response += f"- Events generated: {result.get('event_count', 0)}\n"
                response += f"- Scan time: {result.get('scan_time', 'N/A')}\n"
                
                # Add summary of discovered resources
                recent_events = [e for e in message_broker.events if e['topic'] == 'tool_events' and e['message'].get('event_type') == 'WebResourceDiscovered'][-20:]
                if recent_events:
                    response += f"\n🌐 **Discovered Web Resources:**\n"
                    for event in recent_events:
                        msg = event['message']
                        status = msg.get('status_code', 'N/A')
                        size = msg.get('size', 'N/A')
                        url = msg.get('url', 'N/A')
                        response += f"- [{status}] {url} (Size: {size})\n"
            else:
                response = f"❌ Gobuster scan failed!\n\n"
                response += f"- Return code: {result.get('return_code', 'N/A')}\n"
                if result.get('error'):
                    response += f"- Error: {result.get('error')}\n"
                if result.get('stderr'):
                    response += f"- stderr: {result.get('stderr')}\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Error executing gobuster scan: {e}")
            return [types.TextContent(type="text", text=f"❌ Error executing gobuster scan: {str(e)}")]
    
    elif name == "get_scan_events":
        try:
            event_type_filter = arguments.get('event_type', '')
            limit = arguments.get('limit', 100)
            
            # Filter events
            filtered_events = []
            for event in message_broker.events:
                if event['topic'] == 'tool_events':
                    msg = event['message']
                    if not event_type_filter or msg.get('event_type') == event_type_filter:
                        filtered_events.append(event)
            
            # Limit results
            filtered_events = filtered_events[-limit:]
            
            response = f"📋 **Scan Events** (showing last {len(filtered_events)} events)\n\n"
            
            if not filtered_events:
                response += "No events found matching the criteria.\n"
            else:
                for i, event in enumerate(filtered_events, 1):
                    msg = event['message']
                    event_type = msg.get('event_type', 'Unknown')
                    timestamp = msg.get('timestamp', 'N/A')
                    response += f"{i}. **{event_type}** ({timestamp})\n"
                    
                    # Add event-specific details
                    if event_type in ['HostDiscovered', 'PortFound', 'ServiceDetected', 'VulnerabilityFound']:
                        ip = msg.get('ip', 'N/A')
                        response += f"   IP: {ip}\n"
                        
                        if event_type == 'PortFound':
                            port = msg.get('port', 'N/A')
                            protocol = msg.get('protocol', 'N/A')
                            response += f"   Port: {port}/{protocol}\n"
                        elif event_type == 'ServiceDetected':
                            service = msg.get('service', 'N/A')
                            product = msg.get('product', 'N/A')
                            version = msg.get('version', 'N/A')
                            response += f"   Service: {service} ({product} {version})\n"
                        elif event_type == 'VulnerabilityFound':
                            vuln = msg.get('vulnerability', 'N/A')
                            severity = msg.get('severity', 'N/A')
                            response += f"   Vulnerability: {vuln} (Severity: {severity})\n"
                    elif event_type == 'WebResourceDiscovered':
                        url = msg.get('url', 'N/A')
                        status = msg.get('status_code', 'N/A')
                        size = msg.get('size', 'N/A')
                        response += f"   URL: {url} (Status: {status}, Size: {size})\n"
                    
                    response += "\n"
            
            return [types.TextContent(type="text", text=response)]
            
        except Exception as e:
            logger.error(f"Error retrieving events: {e}")
            return [types.TextContent(type="text", text=f"❌ Error retrieving events: {str(e)}")]
    
    else:
        return [types.TextContent(type="text", text=f"❌ Unknown tool: {name}")]

async def main():
    """Main entry point for the MCP server"""
    # Import here to avoid issues with event loop
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-pentest",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())