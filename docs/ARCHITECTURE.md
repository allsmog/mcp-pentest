# MCP Architecture Guide

This document explains the architecture of the Model Context Provider (MCP) for Penetration Testing.

## System Overview

MCP uses a microservices-based, event-driven architecture deployed in containerized environments. This approach provides flexibility, scalability, and resilience while allowing independent development of components.

![MCP Architecture Diagram](images/architecture-diagram.png)

## Core Components

### 1. Context Processing Engine

**Purpose**: Central data aggregation and normalization engine

**Responsibilities**:
- Subscribe to events from tool integrations
- Transform raw data into unified internal representations
- Store structured data in the appropriate databases
- Track methodology compliance and enforce phase transitions
- Determine next steps in the penetration testing workflow

**Implementation**: Python service using FastAPI with asynchronous event processing

### 2. AI-Powered Attack Path Analyzer

**Purpose**: Identify potential attack paths and prioritize targets

**Responsibilities**:
- Build and maintain a graph of the engagement environment
- Find paths from entry points to critical assets
- Calculate risk scores for vulnerabilities based on context
- Suggest most effective routes for exploitation

**Implementation**: Service connected to Neo4j graph database with specialized algorithms

### 3. Plugin-Based Integration Framework

**Purpose**: Provide extensible tool integration capabilities

**Responsibilities**:
- Execute external security tools with appropriate parameters
- Parse outputs into standardized event formats
- Publish events to the message broker
- Handle error conditions and tool-specific quirks

**Implementation**: Modular plugins for each tool, with sandboxing for safety

### 4. Secure Logging & Reporting Module

**Purpose**: Maintain audit trail and generate reports

**Responsibilities**:
- Log all actions and findings securely
- Generate structured reports with AI assistance
- Sanitize sensitive data before inclusion in reports
- Provide exportable findings in various formats

**Implementation**: Module with templating system and database query capabilities

### 5. Real-Time LLM Query Interface

**Purpose**: Natural language interface for pentesters

**Responsibilities**:
- Process pentester questions about findings and context
- Retrieve relevant data from databases
- Generate contextually-aware responses and suggestions
- Maintain conversation history for coherent assistance

**Implementation**: Service connected to local or cloud-based LLM with RAG capabilities

## Data Flow

1. **Tool Execution & Event Generation**:
   - Tools are executed through their integration plugins
   - Outputs are parsed into standardized events
   - Events are published to the message broker

2. **Context Processing**:
   - The Context Engine subscribes to these events
   - It processes events and stores information in databases
   - Relational data goes to PostgreSQL, graph data to Neo4j

3. **AI Analysis & Assistance**:
   - The Attack Path Analyzer continuously updates the attack graph
   - The LLM Query Interface retrieves context when queried
   - Sanitized data is sent to the LLM for insights
   - Results are presented to the pentester

4. **Reporting**:
   - All findings are logged throughout the engagement
   - At any point, the Reporting Module can generate reports
   - AI assists in summarizing and explaining findings

## Database Structure

MCP uses two primary databases:

1. **PostgreSQL**: For structured, relational data
   - Engagements, hosts, ports, vulnerabilities, credentials
   - Audit logs and user management
   - Task history and tool executions

2. **Neo4j**: For graph-based attack path analysis
   - Hosts, vulnerabilities, and services as nodes
   - Attack vectors and relationships as edges
   - Supports path-finding algorithms for attack route discovery

## Security Design

Security is built into every layer of MCP:

1. **Role-Based Access Control**: Enforced at the API level and within services
2. **Data Encryption**: Sensitive data encrypted at rest and in transit
3. **Sanitization**: Careful data cleaning before sending to external services
4. **Containerization**: Tool execution in isolated environments
5. **Audit Logging**: All actions recorded for accountability

## Extending MCP

The system is designed for extensibility:

1. **Adding Tool Integrations**: Create a new plugin that inherits from the BasePlugin class
2. **Adding Capabilities**: New microservices can subscribe to existing events
3. **Custom AI Models**: The LLM interface can be configured for different models
4. **Report Templates**: The reporting system supports custom templates

See the [Tool Integration Guide](TOOL_INTEGRATION.md) for detailed instructions on adding new tools.

## Deployment Options

MCP supports various deployment scenarios:

1. **Single-Machine**: All components on one system (for individual pentesters)
2. **Team Deployment**: Server-based installation for team collaboration
3. **Distributed**: Components spread across multiple machines for large-scale tests

See the [Deployment Guide](DEPLOYMENT.md) for detailed setup instructions.
