# WebSocket Quick Start Guide

## 🚀 Getting Started with WebSocket Transport

This guide shows you how to quickly start using the WebSocket transport for real-time communication with IDA Headless MCP.

## Prerequisites

- IDA Headless MCP server running
- Go 1.21+ OR Python 3.10+ (depending on which example you want to run)

## Step 1: Start the Server

```powershell
# Build and start the server
cd c:\Users\user\source\repos\ida-headless-mcp\ida-headless-mcp
go build -o bin\ida-mcp-server.exe .\cmd\ida-mcp-server
.\bin\ida-mcp-server.exe --debug
```

You should see:
```
[MCP] Starting IDA Headless MCP Server
[MCP] Listening on :17300
[MCP] HTTP transport at http://localhost:17300/
[MCP] SSE transport at http://localhost:17300/sse
[MCP] WebSocket transport at ws://localhost:17300/ws
```

## Step 2: Run an Example Client

### Option A: Python Client (Recommended for Beginners)

```powershell
# Install dependencies
cd examples\websocket-client
pip install -r requirements.txt

# Run the example
python client.py
```

**Expected Output:**
```
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Starting IDA Headless MCP WebSocket client demonstration
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Connecting to IDA Headless MCP WebSocket server at: ws://localhost:17300/ws
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - WebSocket connection established successfully
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Sending 'tools/list' request to enumerate available MCP tools
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Server reports 52 available tools
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - First 5 tools:
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   1. open_binary: Open binary file for analysis
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   2. close_binary: Close analysis session
...
```

### Option B: Go Client

```powershell
cd examples\websocket-client
go mod download
go run main.go
```

## Step 3: Try Your Own Requests

Modify the example clients to send different MCP requests:

### Python Example - Analyze a Binary

```python
# Open a binary
response = await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="open_binary",
    parameters_for_method_invocation={
        "path": "C:\\path\\to\\your\\binary.exe"
    },
)

session_id = response["session_id"]
print(f"Session opened: {session_id}")

# Get entry point
entry_response = await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="get_entry_point",
    parameters_for_method_invocation={
        "session_id": session_id
    },
)

print(f"Entry point: 0x{entry_response['address']:x}")
```

### Go Example - List Functions

```go
// After opening binary...
requestForFunctionList := map[string]interface{}{
    "method": "get_functions",
    "params": map[string]interface{}{
        "session_id": sessionIdentifier,
        "limit": 10,
    },
}

// Send and process response...
```

## Common Operations

### 1. List All Available Tools
```json
{
    "type": "request",
    "id": "req-001",
    "request": {
        "method": "tools/list",
        "params": {}
    }
}
```

### 2. Open Binary for Analysis
```json
{
    "type": "request",
    "id": "req-002",
    "request": {
        "method": "open_binary",
        "params": {
            "path": "/path/to/binary.exe"
        }
    }
}
```

### 3. Get Functions
```json
{
    "type": "request",
    "id": "req-003",
    "request": {
        "method": "get_functions",
        "params": {
            "session_id": "abc-123-session-id",
            "limit": 100,
            "offset": 0
        }
    }
}
```

### 4. Get Decompiled Code
```json
{
    "type": "request",
    "id": "req-004",
    "request": {
        "method": "get_decompiled_func",
        "params": {
            "session_id": "abc-123-session-id",
            "address": 4198400
        }
    }
}
```

## Testing Connection

### Using WebSocket Command-Line Tools

#### wscat (Node.js)
```powershell
npm install -g wscat
wscat -c ws://localhost:17300/ws
```

Then send:
```json
{"type":"request","id":"test-1","request":{"method":"tools/list","params":{}}}
```

#### websocat (Rust)
```powershell
# Download from: https://github.com/vi/websocat/releases
websocat ws://localhost:17300/ws
```

## Troubleshooting

### Connection Refused
**Problem:** Client cannot connect to `ws://localhost:17300/ws`

**Solution:**
1. Verify server is running: Check terminal for startup messages
2. Check port is correct: Default is 17300
3. Try with `--port` flag: `.\bin\ida-mcp-server.exe --port 17301`

### Timeout Waiting for Response
**Problem:** Client times out waiting for server response

**Solution:**
1. Check server logs with `--debug` flag
2. Increase client timeout duration
3. Verify request format is correct (valid JSON)

### Message Parse Error
**Problem:** Server returns "Failed to parse message JSON"

**Solution:**
1. Ensure message is valid JSON
2. Check message envelope structure matches specification
3. Verify all required fields are present (`type`, `id`, `request`)

### WebSocket Closes Immediately
**Problem:** Connection closes right after establishing

**Solution:**
1. Check server logs for error messages
2. Ensure `Origin` header is acceptable (current implementation allows all)
3. Verify WebSocket protocol version compatibility

## Next Steps

1. **Read Full Documentation**: See [examples/websocket-client/README.md](examples/websocket-client/README.md)
2. **Explore All Tools**: Use `tools/list` to see all 52 available MCP tools
3. **Build Custom Client**: Use examples as templates for your specific use case
4. **Enable Debug Logging**: Add `--debug` flag to server for detailed logs

## Performance Tips

1. **Reuse Connections**: Keep WebSocket connection open for multiple requests
2. **Batch Operations**: Group related requests when possible
3. **Monitor Memory**: Watch connection count in server logs
4. **Set Timeouts**: Always use reasonable timeout values (5-30 seconds typical)

## Support

- **Documentation**: [README.md](README.md)
- **Examples**: [examples/websocket-client/](examples/websocket-client/)
- **Implementation Details**: [WEBSOCKET_IMPLEMENTATION.md](WEBSOCKET_IMPLEMENTATION.md)
- **Issues**: Check server logs with `--debug` flag for detailed error messages

---

**Happy analyzing! 🔍**
