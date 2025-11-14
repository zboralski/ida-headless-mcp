# WebSocket Client Examples for IDA Headless MCP

This directory contains example clients demonstrating how to connect to the IDA Headless MCP server using WebSocket transport for real-time bidirectional communication.

## Why Use WebSocket?

The WebSocket transport (`ws://localhost:17300/ws`) provides several advantages over HTTP/SSE:

- **Bidirectional Communication**: Server can push notifications and updates to clients
- **Lower Latency**: Persistent connection eliminates HTTP handshake overhead
- **Real-Time Updates**: Ideal for streaming analysis progress and large result sets
- **Efficient Resource Usage**: Single persistent connection instead of repeated HTTP requests

## Examples Provided

### 1. Go Client (`main.go`)

A comprehensive Go client demonstrating:
- WebSocket connection establishment with proper error handling
- Request/response correlation using message IDs
- Graceful connection closure
- Timeout handling for responses

**Running the Go Example:**

```powershell
cd examples\websocket-client
go mod download
go run main.go
```

**Expected Output:**
```
2025/11/13 10:30:00 Attempting to connect to IDA Headless MCP WebSocket server at: ws://localhost:17300/ws
2025/11/13 10:30:00 WebSocket connection established successfully, HTTP status code: 101
2025/11/13 10:30:00 Sent request to server, size: 156 bytes, request ID: request-list-tools-001
2025/11/13 10:30:00 Received message #1 from server
2025/11/13 10:30:00 Received message type: response, ID: request-list-tools-001
2025/11/13 10:30:00 Response payload:
{
  "tools": [
    {
      "name": "open_binary",
      "description": "Open binary file for analysis"
    },
    ...
  ]
}
2025/11/13 10:30:00 WebSocket demonstration completed successfully
```

### 2. Python Client (`client.py`)

An async Python client demonstrating:
- Asynchronous WebSocket operations using `asyncio`
- Structured message envelope handling
- Request ID generation and correlation
- Error handling and graceful shutdown

**Running the Python Example:**

```powershell
cd examples\websocket-client
pip install -r requirements.txt
python client.py
```

**Expected Output:**
```
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Starting IDA Headless MCP WebSocket client demonstration
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Connecting to IDA Headless MCP WebSocket server at: ws://localhost:17300/ws
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - WebSocket connection established successfully
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Sending 'tools/list' request to enumerate available MCP tools
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Request sent, awaiting response for: python-ws-request-000001
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Received successful response for request: python-ws-request-000001
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Server reports 52 available tools
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - First 5 tools:
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   1. open_binary: Open binary file for analysis
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   2. close_binary: Close analysis session
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   3. list_sessions: List active analysis sessions
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   4. save_database: Save IDA database
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO -   5. get_bytes: Read bytes at address
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - Closing WebSocket connection gracefully
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - WebSocket connection closed successfully
2025-11-13 10:30:00 - WebSocketClientForIdaHeadlessMcp - INFO - WebSocket client demonstration completed successfully
```

## WebSocket Message Protocol

All messages use a JSON envelope structure:

### Request Message

```json
{
  "type": "request",
  "id": "unique-request-identifier-12345",
  "request": {
    "method": "tools/list",
    "params": {}
  }
}
```

### Response Message (Success)

```json
{
  "type": "response",
  "id": "unique-request-identifier-12345",
  "response": {
    "tools": [...]
  }
}
```

### Response Message (Error)

```json
{
  "type": "error",
  "id": "unique-request-identifier-12345",
  "error": {
    "message": "Error description here"
  }
}
```

## Advanced Usage Patterns

### 1. Binary Analysis Workflow

```python
# Open binary
response_from_open_binary = await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="open_binary",
    parameters_for_method_invocation={
        "path": "/path/to/binary.exe"
    },
)

session_identifier_from_response = response_from_open_binary["session_id"]

# Run auto-analysis
await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="run_auto_analysis",
    parameters_for_method_invocation={
        "session_id": session_identifier_from_response
    },
)

# Get functions
functions_response = await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="get_functions",
    parameters_for_method_invocation={
        "session_id": session_identifier_from_response,
        "limit": 100
    },
)
```

### 2. Concurrent Requests

WebSocket maintains a single persistent connection, but you can send multiple requests and correlate responses using unique IDs:

```python
request_id_for_functions = client.generate_unique_request_identifier_for_new_request()
request_id_for_strings = client.generate_unique_request_identifier_for_new_request()

# Send both requests
await send_request_without_waiting(request_id_for_functions, "get_functions", {...})
await send_request_without_waiting(request_id_for_strings, "get_strings", {...})

# Process responses as they arrive (potentially out of order)
```

### 3. Long-Running Operations with Progress Updates

For operations that take significant time (like auto-analysis), you can monitor progress:

```python
# Start auto-analysis
await client.send_request_to_server_and_wait_for_response(
    method_name_for_remote_procedure_call="watch_auto_analysis",
    parameters_for_method_invocation={
        "session_id": session_identifier_from_response
    },
)

# Server may send progress notifications during processing
# (Implementation depends on server-side streaming support)
```

## Connection Configuration

### Timeouts

The examples use the following timeout values:

- **Handshake Timeout**: 10 seconds (Go), configurable (Python)
- **Read Timeout**: 60 seconds (pong wait)
- **Write Timeout**: 10 seconds per message
- **Ping Interval**: 30 seconds (keep-alive)

### Buffer Sizes

Server configuration (from `websocket.go`):

- **Read Buffer**: 4096 bytes
- **Write Buffer**: 4096 bytes
- **Maximum Message Size**: 1,048,576 bytes (1 MB)
- **Outgoing Message Queue**: 256 messages buffered

## Error Handling Best Practices

1. **Connection Failures**: Always wrap connection establishment in try-catch
2. **Timeout Handling**: Set appropriate timeouts for long-running operations
3. **Graceful Shutdown**: Always close connections properly to free server resources
4. **Request ID Correlation**: Verify response IDs match request IDs
5. **Message Parsing**: Handle JSON parsing errors gracefully

## Debugging Tips

### Enable Debug Logging

**Go:**
```go
// Messages are logged automatically in the example
```

**Python:**
```python
logging.basicConfig(level=logging.DEBUG)  # Change from INFO to DEBUG
```

### Monitor Server Logs

Start the IDA MCP server with debug flag:
```powershell
.\bin\ida-mcp-server.exe --debug
```

Look for WebSocket-specific log entries:
```
[WEBSOCKET] Received WebSocket upgrade request from remote client address: 127.0.0.1:52341
[WEBSOCKET] Successfully established WebSocket connection with identifier: ws-connection-1
[WEBSOCKET] Received message from connection ws-connection-1, size: 156 bytes
[WEBSOCKET] Processing MCP request python-ws-request-000001 from connection ws-connection-1
```

### Common Issues

**Issue**: Connection refused
**Solution**: Ensure IDA MCP server is running on port 17300

**Issue**: Timeout waiting for response
**Solution**: Increase timeout duration or check server logs for errors

**Issue**: Message ID mismatch
**Solution**: Ensure unique request IDs and proper correlation logic

## Performance Considerations

- **Connection Pooling**: Single WebSocket connection can handle multiple sequential requests
- **Message Queue**: Server buffers up to 256 outgoing messages per connection
- **Automatic Cleanup**: Server automatically closes idle connections after timeout
- **Resource Limits**: Monitor active connection count via server logs

## See Also

- [Main README](../../README.md) - General project documentation
- [MCP Specification](https://spec.modelcontextprotocol.io/) - Model Context Protocol details
- [WebSocket RFC 6455](https://tools.ietf.org/html/rfc6455) - WebSocket protocol specification
