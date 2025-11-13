#!/usr/bin/env python3
"""
Test the Python worker's protobuf serialization.

This test verifies that issue #25 is fixed by:
1. Starting a worker process with a test binary
2. Sending Connect RPC requests with protobuf encoding
3. Verifying responses use application/proto content-type
4. Validating protobuf response parsing

Run this test to ensure the worker correctly handles protobuf serialization.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Add protobuf generated code to path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR / "python/worker/gen"))

try:
    import ida_service_pb2 as pb
except ImportError:
    print("Error: Protobuf generated code not found.")
    print("Run 'make proto' to generate python/worker/gen/ida_service_pb2.py")
    sys.exit(1)

# Test configuration
WORKER_SCRIPT = SCRIPT_DIR / "python/worker/server.py"
TEST_SOCKET = "/tmp/test-ida-worker-protobuf.sock"
SESSION_ID = "test-protobuf"

# Find a test binary
SAMPLE_PATHS = [
    SCRIPT_DIR.parent / "samples/libcocos2dlua-71cfb5834918bc85ed833ca82917cf67b0bd5f3ff66684f540cf80fd91c259ea.so",
    "/bin/ls",  # Fallback
]
TEST_BINARY = None
for path in SAMPLE_PATHS:
    if path.exists():
        TEST_BINARY = str(path)
        break

if not TEST_BINARY:
    print("Error: No test binary found")
    sys.exit(1)


def send_connect_rpc(sock, service, method, request_pb):
    """Send a Connect RPC request over Unix socket and return response"""
    # Serialize protobuf request
    body = request_pb.SerializeToString()

    # Build HTTP POST request
    path = f"/idagrpc.v1.{service}/{method}"
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: unix\r\n"
        f"Content-Type: application/proto\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    # Send request
    sock.sendall(request)

    # Read response
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

        # Check if we have complete response
        if b"\r\n\r\n" in response:
            headers_end = response.find(b"\r\n\r\n")
            headers = response[:headers_end]
            body_start = headers_end + 4

            # Parse Content-Length
            for line in headers.split(b"\r\n"):
                if line.startswith(b"Content-Length:"):
                    content_length = int(line.split(b":")[1].strip())
                    body_received = len(response) - body_start
                    if body_received >= content_length:
                        return response

    return response


def parse_http_response(response_bytes):
    """Parse HTTP response and extract status, headers, and body"""
    if b"\r\n\r\n" not in response_bytes:
        raise Exception("Invalid HTTP response: missing header/body separator")

    headers_part, body = response_bytes.split(b"\r\n\r\n", 1)
    header_lines = headers_part.split(b"\r\n")

    # Parse status line
    status_line = header_lines[0].decode()
    parts = status_line.split(" ", 2)
    status_code = int(parts[1])

    # Parse headers
    headers = {}
    for line in header_lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode().strip()] = value.strip().decode()

    return status_code, headers, body


def test_protobuf_serialization():
    """Main test function"""
    print("=" * 60)
    print("TESTING PYTHON WORKER PROTOBUF SERIALIZATION")
    print("=" * 60)
    print(f"\nTest binary: {TEST_BINARY}")
    print(f"Worker script: {WORKER_SCRIPT}")

    # Clean up old socket
    if os.path.exists(TEST_SOCKET):
        os.remove(TEST_SOCKET)

    # Clean up old IDA database files
    binary_path = Path(TEST_BINARY)
    for ext in [".id0", ".id1", ".id2", ".nam", ".til", ".i64"]:
        db_file = binary_path.parent / (binary_path.name + ext)
        if db_file.exists():
            db_file.unlink()
            print(f"      Removed old database: {db_file.name}")

    # Start worker process
    print(f"\n[1/5] Starting worker process...")
    worker_cmd = [
        "python3",
        str(WORKER_SCRIPT),
        "--socket", TEST_SOCKET,
        "--binary", TEST_BINARY,
        "--session-id", SESSION_ID,
    ]

    worker_proc = subprocess.Popen(
        worker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for socket to be created
    print(f"[2/5] Waiting for worker socket...")
    socket_ready = False
    for i in range(20):
        if os.path.exists(TEST_SOCKET):
            socket_ready = True
            break
        time.sleep(0.5)
        # Check if process died
        if worker_proc.poll() is not None:
            stdout, stderr = worker_proc.communicate()
            print("FAIL: Worker process exited")
            print("STDOUT:", stdout.decode())
            print("STDERR:", stderr.decode())
            return False

    if not socket_ready:
        worker_proc.kill()
        stdout, stderr = worker_proc.communicate()
        print("FAIL: Worker socket did not appear")
        print("STDOUT:", stdout.decode())
        print("STDERR:", stderr.decode())
        return False

    print(f"      Socket created: {TEST_SOCKET}")

    try:
        # Connect to worker
        print(f"[3/5] Connecting to worker...")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(TEST_SOCKET)
        print(f"      Connected")

        # Test 1: OpenBinary with protobuf
        print(f"\n[4/5] Testing OpenBinary RPC with protobuf...")
        req = pb.OpenBinaryRequest()
        req.binary_path = TEST_BINARY
        req.auto_analyze = False

        response = send_connect_rpc(sock, "SessionControl", "OpenBinary", req)
        status_code, headers, body = parse_http_response(response)

        print(f"      HTTP Status: {status_code}")
        print(f"      Content-Type: {headers.get('Content-Type', 'MISSING')}")

        # Verify status
        if status_code != 200:
            print(f"FAIL: Expected status 200, got {status_code}")
            return False

        # Verify Content-Type header
        if headers.get("Content-Type") != "application/proto":
            print(f"FAIL: Expected 'application/proto', got '{headers.get('Content-Type')}'")
            return False

        print(f"      PASS: Correct Content-Type header")

        # Parse protobuf response
        resp = pb.OpenBinaryResponse()
        try:
            resp.ParseFromString(body)
        except Exception as e:
            print(f"FAIL: Could not parse protobuf response: {e}")
            return False

        print(f"      Response parsed successfully:")
        print(f"        success: {resp.success}")
        print(f"        has_decompiler: {resp.has_decompiler}")
        print(f"        binary_path: {resp.binary_path}")

        if not resp.success:
            print(f"FAIL: OpenBinary reported failure")
            if resp.error:
                print(f"      Error: {resp.error}")
            return False

        print(f"      PASS: OpenBinary succeeded")

        # Test 2: Ping with protobuf (need new connection)
        print(f"\n[5/5] Testing Ping RPC with protobuf...")
        sock.close()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(TEST_SOCKET)

        req = pb.PingRequest()
        response = send_connect_rpc(sock, "Healthcheck", "Ping", req)
        status_code, headers, body = parse_http_response(response)

        if status_code != 200:
            print(f"FAIL: Ping returned status {status_code}")
            return False

        if headers.get("Content-Type") != "application/proto":
            print(f"FAIL: Ping wrong Content-Type: {headers.get('Content-Type')}")
            return False

        resp = pb.PingResponse()
        resp.ParseFromString(body)

        if not resp.alive:
            print(f"FAIL: Ping returned alive=false")
            return False

        print(f"      PASS: Ping succeeded")

        # All tests passed
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
        print("\nThe Python worker correctly:")
        print("  - Accepts protobuf requests")
        print("  - Returns 'application/proto' Content-Type")
        print("  - Serializes responses as valid protobuf")
        print("\nIssue #25 is verified as fixed.")
        return True

    finally:
        sock.close()
        worker_proc.terminate()
        worker_proc.wait(timeout=5)
        if os.path.exists(TEST_SOCKET):
            os.remove(TEST_SOCKET)


if __name__ == "__main__":
    try:
        success = test_protobuf_serialization()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nTest failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
