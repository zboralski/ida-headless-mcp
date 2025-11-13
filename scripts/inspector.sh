#!/bin/bash
# Start MCP Inspector for testing the IDA Headless MCP server
# https://github.com/modelcontextprotocol/inspector

set -e

# Check if server is running
if ! lsof -i :17300 > /dev/null 2>&1; then
    echo "Error: IDA MCP server not running on port 17300"
    echo "Start the server first with: make run"
    exit 1
fi

# Check if npx is available
if ! command -v npx &> /dev/null; then
    echo "Error: npx not found. Install Node.js first:"
    echo "  brew install node"
    exit 1
fi

echo "Starting MCP Inspector..."
echo ""
echo "Open this URL in your browser to connect via StreamableHTTP:"
echo "  http://localhost:6274/?transport=streamable-http&serverUrl=http://localhost:17300/"
echo ""

# Start inspector
DANGEROUSLY_OMIT_AUTH=true npx @modelcontextprotocol/inspector
