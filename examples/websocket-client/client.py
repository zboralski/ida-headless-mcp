import asyncio
import json
import logging
import signal
import sys
from typing import Dict, Any, Optional

try:
    import websockets
except ImportError:
    print("ERROR: websockets library not installed")
    print("Install with: pip install websockets")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger_for_websocket_client_operations = logging.getLogger('WebSocketClientForIdaHeadlessMcp')


class WebSocketMessageEnvelopeForModelContextProtocol:
    def __init__(
        self,
        message_type_identifier_string: str,
        message_identifier_for_request_response_correlation: Optional[str] = None,
        model_context_protocol_request_payload: Optional[Dict[str, Any]] = None,
        model_context_protocol_response_payload: Optional[Dict[str, Any]] = None,
        model_context_protocol_error_payload: Optional[Dict[str, Any]] = None,
    ):
        self.message_type_identifier_string = message_type_identifier_string
        self.message_identifier_for_request_response_correlation = message_identifier_for_request_response_correlation
        self.model_context_protocol_request_payload = model_context_protocol_request_payload
        self.model_context_protocol_response_payload = model_context_protocol_response_payload
        self.model_context_protocol_error_payload = model_context_protocol_error_payload

    def serialize_to_json_string_for_transmission(self) -> str:
        dictionary_representation_of_message_envelope = {
            "type": self.message_type_identifier_string,
        }

        message_identifier_is_not_none = self.message_identifier_for_request_response_correlation is not None
        if message_identifier_is_not_none:
            dictionary_representation_of_message_envelope["id"] = self.message_identifier_for_request_response_correlation

        request_payload_is_not_none = self.model_context_protocol_request_payload is not None
        if request_payload_is_not_none:
            dictionary_representation_of_message_envelope["request"] = self.model_context_protocol_request_payload

        response_payload_is_not_none = self.model_context_protocol_response_payload is not None
        if response_payload_is_not_none:
            dictionary_representation_of_message_envelope["response"] = self.model_context_protocol_response_payload

        error_payload_is_not_none = self.model_context_protocol_error_payload is not None
        if error_payload_is_not_none:
            dictionary_representation_of_message_envelope["error"] = self.model_context_protocol_error_payload

        json_string_representation_of_envelope = json.dumps(dictionary_representation_of_message_envelope)
        return json_string_representation_of_envelope


class IdaHeadlessMcpWebSocketClient:
    def __init__(
        self,
        websocket_server_url_for_connection: str,
        should_enable_verbose_debug_logging: bool = False,
    ):
        self.websocket_server_url_for_connection = websocket_server_url_for_connection
        self.should_enable_verbose_debug_logging = should_enable_verbose_debug_logging
        self.websocket_connection_to_server: Optional[Any] = None
        self.is_client_currently_connected_to_server = False
        self.next_request_identifier_number_for_sequential_assignment = 1

    async def establish_connection_to_websocket_server(self):
        log_message_indicating_connection_attempt = f"Connecting to IDA Headless MCP WebSocket server at: {self.websocket_server_url_for_connection}"
        logger_for_websocket_client_operations.info(log_message_indicating_connection_attempt)

        try:
            websocket_connection_instance = await websockets.connect(
                self.websocket_server_url_for_connection,
                ping_interval=30,
                ping_timeout=60,
            )

            self.websocket_connection_to_server = websocket_connection_instance
            self.is_client_currently_connected_to_server = True

            logger_for_websocket_client_operations.info("WebSocket connection established successfully")

        except Exception as exception_from_connection_attempt:
            error_message_describing_connection_failure = f"Failed to establish WebSocket connection: {exception_from_connection_attempt}"
            logger_for_websocket_client_operations.error(error_message_describing_connection_failure)
            raise

    async def send_request_to_server_and_wait_for_response(
        self,
        method_name_for_remote_procedure_call: str,
        parameters_for_method_invocation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        connection_is_not_established = not self.is_client_currently_connected_to_server
        if connection_is_not_established:
            error_message_indicating_no_connection = "Cannot send request: WebSocket connection not established"
            raise RuntimeError(error_message_indicating_no_connection)

        unique_request_identifier = self.generate_unique_request_identifier_for_new_request()

        parameters_dictionary_or_empty_dict = parameters_for_method_invocation if parameters_for_method_invocation is not None else {}

        model_context_protocol_request_structure = {
            "method": method_name_for_remote_procedure_call,
            "params": parameters_dictionary_or_empty_dict,
        }

        message_envelope_for_request = WebSocketMessageEnvelopeForModelContextProtocol(
            message_type_identifier_string="request",
            message_identifier_for_request_response_correlation=unique_request_identifier,
            model_context_protocol_request_payload=model_context_protocol_request_structure,
        )

        json_string_to_send_to_server = message_envelope_for_request.serialize_to_json_string_for_transmission()

        if self.should_enable_verbose_debug_logging:
            log_message_with_request_details = f"Sending request: {method_name_for_remote_procedure_call}, ID: {unique_request_identifier}"
            logger_for_websocket_client_operations.debug(log_message_with_request_details)

        await self.websocket_connection_to_server.send(json_string_to_send_to_server)

        logger_for_websocket_client_operations.info(f"Request sent, awaiting response for: {unique_request_identifier}")

        response_payload_from_server = await self.receive_and_process_response_from_server(unique_request_identifier)

        return response_payload_from_server

    async def receive_and_process_response_from_server(
        self,
        expected_request_identifier_for_correlation: str,
    ) -> Dict[str, Any]:
        maximum_number_of_messages_to_receive_while_waiting = 100
        number_of_messages_received_so_far = 0

        while number_of_messages_received_so_far < maximum_number_of_messages_to_receive_while_waiting:
            number_of_messages_received_so_far = number_of_messages_received_so_far + 1

            message_string_from_server = await self.websocket_connection_to_server.recv()

            if self.should_enable_verbose_debug_logging:
                message_size_in_bytes = len(message_string_from_server)
                log_message_with_received_message_details = f"Received message from server, size: {message_size_in_bytes} bytes"
                logger_for_websocket_client_operations.debug(log_message_with_received_message_details)

            parsed_message_envelope_dictionary = json.loads(message_string_from_server)

            message_type_string = parsed_message_envelope_dictionary.get("type")
            message_identifier_from_envelope = parsed_message_envelope_dictionary.get("id")

            message_identifier_matches_expected = message_identifier_from_envelope == expected_request_identifier_for_correlation

            if not message_identifier_matches_expected:
                log_message_about_mismatched_identifier = f"Received message with mismatched ID: {message_identifier_from_envelope}, expected: {expected_request_identifier_for_correlation}"
                logger_for_websocket_client_operations.warning(log_message_about_mismatched_identifier)
                continue

            message_is_response_type = message_type_string == "response"
            message_is_error_type = message_type_string == "error"

            if message_is_response_type:
                response_payload_from_message = parsed_message_envelope_dictionary.get("response", {})
                logger_for_websocket_client_operations.info(f"Received successful response for request: {expected_request_identifier_for_correlation}")
                return response_payload_from_message

            if message_is_error_type:
                error_payload_from_message = parsed_message_envelope_dictionary.get("error", {})
                error_message_from_payload = error_payload_from_message.get("message", "Unknown error")
                error_description_for_exception = f"Server returned error: {error_message_from_payload}"
                raise RuntimeError(error_description_for_exception)

        error_message_for_timeout = f"Timeout waiting for response to request: {expected_request_identifier_for_correlation}"
        raise TimeoutError(error_message_for_timeout)

    def generate_unique_request_identifier_for_new_request(self) -> str:
        current_request_number = self.next_request_identifier_number_for_sequential_assignment
        self.next_request_identifier_number_for_sequential_assignment = current_request_number + 1

        request_identifier_as_string = f"python-ws-request-{current_request_number:06d}"
        return request_identifier_as_string

    async def close_connection_to_server_gracefully(self):
        connection_is_currently_established = self.is_client_currently_connected_to_server
        if connection_is_currently_established:
            logger_for_websocket_client_operations.info("Closing WebSocket connection gracefully")
            await self.websocket_connection_to_server.close()
            self.is_client_currently_connected_to_server = False
            logger_for_websocket_client_operations.info("WebSocket connection closed successfully")


async def demonstrate_websocket_client_operations_with_ida_headless_mcp():
    websocket_server_url_for_connection = "ws://localhost:17300/ws"
    should_enable_verbose_debug_logging = True

    websocket_client_instance = IdaHeadlessMcpWebSocketClient(
        websocket_server_url_for_connection=websocket_server_url_for_connection,
        should_enable_verbose_debug_logging=should_enable_verbose_debug_logging,
    )

    try:
        await websocket_client_instance.establish_connection_to_websocket_server()

        logger_for_websocket_client_operations.info("Sending 'tools/list' request to enumerate available MCP tools")

        response_payload_from_list_tools_request = await websocket_client_instance.send_request_to_server_and_wait_for_response(
            method_name_for_remote_procedure_call="tools/list",
            parameters_for_method_invocation={},
        )

        tools_array_from_response = response_payload_from_list_tools_request.get("tools", [])
        number_of_tools_available = len(tools_array_from_response)

        logger_for_websocket_client_operations.info(f"Server reports {number_of_tools_available} available tools")

        if number_of_tools_available > 0:
            logger_for_websocket_client_operations.info("First 5 tools:")
            maximum_tools_to_display = min(5, number_of_tools_available)
            for tool_index in range(maximum_tools_to_display):
                tool_structure = tools_array_from_response[tool_index]
                tool_name = tool_structure.get("name", "unknown")
                tool_description = tool_structure.get("description", "No description")
                log_message_with_tool_info = f"  {tool_index + 1}. {tool_name}: {tool_description}"
                logger_for_websocket_client_operations.info(log_message_with_tool_info)

    except Exception as exception_during_demonstration:
        error_message_describing_exception = f"Error during WebSocket demonstration: {exception_during_demonstration}"
        logger_for_websocket_client_operations.error(error_message_describing_exception)
        raise

    finally:
        await websocket_client_instance.close_connection_to_server_gracefully()


def main_entry_point_for_websocket_client_demonstration():
    logger_for_websocket_client_operations.info("Starting IDA Headless MCP WebSocket client demonstration")

    try:
        asyncio.run(demonstrate_websocket_client_operations_with_ida_headless_mcp())
        logger_for_websocket_client_operations.info("WebSocket client demonstration completed successfully")

    except KeyboardInterrupt:
        logger_for_websocket_client_operations.info("Demonstration interrupted by user")

    except Exception as exception_from_main:
        error_message_for_uncaught_exception = f"Uncaught exception in main: {exception_from_main}"
        logger_for_websocket_client_operations.error(error_message_for_uncaught_exception)
        sys.exit(1)


if __name__ == "__main__":
    main_entry_point_for_websocket_client_demonstration()
