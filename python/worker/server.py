#!/usr/bin/env python3
"""
Python Connect RPC Worker for IDA Headless Analysis
Serves Connect RPC over Unix domain socket
"""

import argparse
import logging
import os
import socket
import sys
import time
from pathlib import Path

# Add proto path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "proto"))

try:
    import idapro
except ImportError:
    print("Error: idapro module not found. Run setup_idalib.sh first")
    sys.exit(1)

from connect_server import ConnectServer
from ida_wrapper import IDAWrapper

def serve_on_unix_socket(socket_path: str, handler, session_id: str):
    """Serve Connect RPC over Unix domain socket"""

    # Remove existing socket
    if os.path.exists(socket_path):
        os.remove(socket_path)

    # Create Unix socket
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_socket.bind(socket_path)
    server_socket.listen(5)

    logging.info(f"[Worker {session_id}] Listening on {socket_path}")

    try:
        while True:
            conn, _ = server_socket.accept()
            # Handle HTTP/1.1 request over socket
            handle_connection(conn, handler)
    finally:
        server_socket.close()
        if os.path.exists(socket_path):
            os.remove(socket_path)

def handle_connection(conn: socket.socket, handler):
    """Handle single HTTP connection"""
    try:
        # Read HTTP request
        request_data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            request_data += chunk
            # Simple check for end of headers
            if b"\r\n\r\n" in request_data:
                # Check Content-Length to read body
                headers = request_data.split(b"\r\n\r\n")[0]
                if b"Content-Length:" in headers:
                    for line in headers.split(b"\r\n"):
                        if line.startswith(b"Content-Length:"):
                            content_length = int(line.split(b":")[1].strip())
                            body_start = request_data.find(b"\r\n\r\n") + 4
                            body_received = len(request_data) - body_start
                            if body_received < content_length:
                                # Read remaining body
                                remaining = content_length - body_received
                                request_data += conn.recv(remaining)
                break

        if not request_data:
            return

        # Parse HTTP request (simplified)
        lines = request_data.split(b"\r\n")
        request_line = lines[0].decode('utf-8')
        method, path, _ = request_line.split()

        # Route to handler
        response = handler(method, path, request_data)

        # Send HTTP response
        conn.sendall(response.encode() if isinstance(response, str) else response)

    except Exception as e:
        logging.error(f"Connection error: {e}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="IDA Connect Worker")
    parser.add_argument("--socket", required=True, help="Unix socket path")
    parser.add_argument("--binary", required=True, help="Binary file path")
    parser.add_argument("--session-id", required=True, help="Session ID")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format=f'[Worker {args.session_id}] %(asctime)s - %(levelname)s - %(message)s'
    )

    logging.info(f"Starting worker for binary: {args.binary}")
    logging.info("Initializing Connect server (IDA database will open on demand)")

    # Initialize IDA wrapper (database opens when OpenBinary is called)
    ida = IDAWrapper(args.binary, args.session_id)

    # Create Connect server
    server = ConnectServer(ida)

    # Simple HTTP handler
    def handle_request(method: str, path: str, data: bytes) -> bytes:
        return server.handle(method, path, data)

    try:
        serve_on_unix_socket(args.socket, handle_request, args.session_id)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        ida.close_database()
        logging.info("Worker terminated")


if __name__ == "__main__":
    main()
