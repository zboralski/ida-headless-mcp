"""
Connect RPC Server
Implements SessionControl, AnalysisTools, and Healthcheck services
"""

import logging
import sys
import time
from pathlib import Path

# Add gen path for protobuf imports
sys.path.insert(0, str(Path(__file__).parent / "gen"))

from ida.worker.v1 import service_pb2 as pb


class ConnectServer:
    """Simple Connect RPC handler over HTTP"""

    def __init__(self, ida_wrapper):
        self.ida = ida_wrapper
        self.pending_requests = 0

    def _ensure_database_open(self, auto_analyze: bool) -> tuple[bool, str | None]:
        """Ensure the IDA database is open before servicing requests."""
        if self.ida.db_open:
            return True, None
        success = self.ida.open_database(auto_analyze)
        if success:
            return True, None
        return False, self.ida.last_error or "Failed to open IDA database"

    def _require_open_database(self):
        if self.ida.db_open:
            return
        success, error = self._ensure_database_open(auto_analyze=False)
        if not success:
            raise RuntimeError(error or "IDA database is not open. Call OpenBinary first.")

    def handle(self, method: str, path: str, data: bytes) -> bytes:
        """Handle Connect RPC request"""
        try:
            self.pending_requests += 1

            # Parse service and method from path
            # Path format: /idagrpc.v1.ServiceName/MethodName
            parts = path.split("/")
            if len(parts) < 3:
                return self._error_response(400, "Invalid path")

            service = parts[-2].split(".")[-1]  # Extract ServiceName
            rpc_method = parts[-1]

            # Extract protobuf body from HTTP request
            proto_body = self._extract_body(data)

            # Route to appropriate handler
            if service == "SessionControl":
                response_pb = self._handle_session_control(rpc_method, proto_body)
            elif service == "AnalysisTools":
                response_pb = self._handle_analysis_tools(rpc_method, proto_body)
            elif service == "Healthcheck":
                response_pb = self._handle_healthcheck(rpc_method, proto_body)
            else:
                return self._error_response(404, f"Unknown service: {service}")

            return self._success_response(response_pb)

        except Exception as e:
            logging.error(f"Error handling request: {e}", exc_info=True)
            return self._error_response(500, str(e))
        finally:
            self.pending_requests -= 1

    def _handle_session_control(self, method: str, proto_body: bytes):
        """Handle SessionControl RPC - returns protobuf message"""
        if method == "OpenBinary":
            req = pb.OpenBinaryRequest()
            req.ParseFromString(proto_body)
            resp = pb.OpenBinaryResponse()

            success, error = self._ensure_database_open(req.auto_analyze)
            resp.success = success
            resp.binary_path = self.ida.binary_path

            if success:
                resp.has_decompiler = self.ida.has_decompiler
            else:
                resp.error = error or "Failed to open IDA database"
            return resp

        elif method == "CloseSession":
            req = pb.CloseSessionRequest()
            req.ParseFromString(proto_body)
            if not self.ida.db_open:
                success = True
            else:
                success = self.ida.close_database(req.save)
            resp = pb.CloseSessionResponse()
            resp.success = success
            return resp

        elif method == "SaveDatabase":
            self._require_open_database()
            success, timestamp, dirty = self.ida.save_database()
            resp = pb.SaveDatabaseResponse()
            resp.success = success
            resp.timestamp = timestamp
            resp.dirty = dirty
            if not success:
                resp.error = "Failed to save database"
            return resp

        elif method == "PlanAndWait":
            self._require_open_database()
            success, duration, error = self.ida.plan_and_wait()
            resp = pb.PlanAndWaitResponse()
            resp.success = success
            resp.duration_seconds = duration
            if error:
                resp.error = error
            return resp

        elif method == "GetSessionInfo":
            resp = pb.GetSessionInfoResponse()
            resp.binary_path = self.ida.binary_path
            resp.opened_at = int(self.ida.opened_at or 0)
            resp.last_activity = int(self.ida.last_activity or 0)
            resp.has_decompiler = self.ida.has_decompiler
            auto_running, auto_state = self.ida.get_auto_status()
            resp.auto_running = auto_running
            resp.auto_state = auto_state
            return resp

        else:
            raise Exception(f"Unknown method: {method}")

    def _handle_analysis_tools(self, method: str, proto_body: bytes):
        """Handle AnalysisTools RPC - returns protobuf message"""
        try:
            self._require_open_database()
            if method == "GetBytes":
                req = pb.GetBytesRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_bytes(req.address, req.size)
                resp = pb.GetBytesResponse()
                resp.data = bytes(result)
                return resp

            elif method == "GetDisasm":
                req = pb.GetDisasmRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_disasm(req.address)
                resp = pb.GetDisasmResponse()
                resp.disasm = result
                return resp

            elif method == "GetFunctionDisasm":
                req = pb.GetFunctionDisasmRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_function_disasm(req.address)
                resp = pb.GetFunctionDisasmResponse()
                resp.disassembly = result
                return resp

            elif method == "GetDecompiled":
                req = pb.GetDecompiledRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_decompiled(req.address)
                resp = pb.GetDecompiledResponse()
                resp.code = result
                return resp

            elif method == "GetFunctionName":
                req = pb.GetFunctionNameRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_function_name(req.address)
                resp = pb.GetFunctionNameResponse()
                resp.name = result
                return resp

            elif method == "GetSegments":
                result = self.ida.get_segments()
                resp = pb.GetSegmentsResponse()
                for seg in result:
                    seg_pb = resp.segments.add()
                    seg_pb.start = seg["start"]
                    seg_pb.end = seg["end"]
                    seg_pb.name = seg["name"]
                    seg_class = seg.get("seg_class", 0)
                    seg_pb.seg_class = str(seg_class) if seg_class is not None else ""
                    seg_pb.permissions = seg.get("permissions", 0)
                    seg_pb.bitness = seg.get("bitness", 0)
                return resp

            elif method == "GetFunctions":
                result = self.ida.get_functions()
                resp = pb.GetFunctionsResponse()
                for func in result:
                    func_pb = resp.functions.add()
                    func_pb.address = func["address"]
                    func_pb.name = func["name"]
                return resp

            elif method == "GetXRefsTo":
                req = pb.GetXRefsToRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_xrefs_to(req.address)
                resp = pb.GetXRefsToResponse()
                for xref in result:
                    xref_pb = resp.xrefs.add()
                    setattr(xref_pb, "from", xref["from"])
                    xref_pb.to = xref.get("to", req.address)
                    xref_pb.type = xref["type"]
                return resp

            elif method == "GetXRefsFrom":
                req = pb.GetXRefsFromRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_xrefs_from(req.address)
                resp = pb.GetXRefsFromResponse()
                for xref in result:
                    xref_pb = resp.xrefs.add()
                    setattr(xref_pb, "from", xref["from"])
                    xref_pb.to = xref["to"]
                    xref_pb.type = xref["type"]
                return resp

            elif method == "GetDataRefs":
                req = pb.GetDataRefsRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_data_refs(req.address)
                resp = pb.GetDataRefsResponse()
                for ref in result:
                    ref_pb = resp.refs.add()
                    setattr(ref_pb, "from", ref["from"])
                    ref_pb.type = ref["type"]
                return resp

            elif method == "GetStringXRefs":
                req = pb.GetStringXRefsRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_string_xrefs(req.address)
                resp = pb.GetStringXRefsResponse()
                for ref in result:
                    ref_pb = resp.refs.add()
                    ref_pb.address = ref["address"]
                    ref_pb.function_address = ref["function_address"]
                    ref_pb.function_name = ref["function_name"]
                return resp

            elif method == "ImportIl2Cpp":
                req = pb.ImportIl2CppRequest()
                req.ParseFromString(proto_body)
                script_path = req.script_path
                header_path = req.il2cpp_path
                if not script_path or not header_path:
                    raise ValueError("script_path and il2cpp_path are required")
                with open(script_path, "r", encoding="utf-8") as f:
                    script_json = f.read()
                with open(header_path, "r", encoding="utf-8") as f:
                    header = f.read()
                result = self.ida.import_il2cpp(script_json, header, list(req.fields))
                resp = pb.ImportIl2CppResponse()
                resp.success = True
                resp.duration_seconds = result.get("duration_seconds", 0.0)
                resp.functions_defined = result.get("functions_defined", 0)
                resp.functions_named = result.get("functions_named", 0)
                resp.strings_named = result.get("strings_named", 0)
                resp.metadata_named = result.get("metadata_named", 0)
                resp.metadata_methods = result.get("metadata_methods", 0)
                resp.signatures_applied = result.get("signatures_applied", 0)
                if result.get("header_error"):
                    resp.error = result["header_error"]
                return resp

            elif method == "ImportFlutter":
                req = pb.ImportFlutterRequest()
                req.ParseFromString(proto_body)
                blutter_output_path = req.blutter_output_path
                if not blutter_output_path:
                    raise ValueError("blutter_output_path is required")
                result = self.ida.import_flutter(blutter_output_path)
                resp = pb.ImportFlutterResponse()
                resp.success = True
                resp.duration_seconds = result.get("duration_seconds", 0.0)
                resp.functions_created = result.get("functions_created", 0)
                resp.functions_named = result.get("functions_named", 0)
                return resp

            elif method == "GetImports":
                result = self.ida.get_imports()
                resp = pb.GetImportsResponse()
                for imp in result:
                    imp_pb = resp.imports.add()
                    imp_pb.module = imp.get("module", "")
                    imp_pb.address = imp["address"]
                    imp_pb.name = imp["name"]
                    imp_pb.ordinal = imp.get("ordinal", 0)
                return resp

            elif method == "GetExports":
                result = self.ida.get_exports()
                resp = pb.GetExportsResponse()
                for exp in result:
                    exp_pb = resp.exports.add()
                    exp_pb.index = exp.get("index", 0)
                    exp_pb.ordinal = exp["ordinal"]
                    exp_pb.address = exp["address"]
                    exp_pb.name = exp["name"]
                return resp

            elif method == "GetEntryPoint":
                result = self.ida.get_entry_point()
                resp = pb.GetEntryPointResponse()
                resp.address = result
                return resp

            elif method == "GetStrings":
                req = pb.GetStringsRequest()
                req.ParseFromString(proto_body)

                # Use default values if not provided
                offset = req.offset if req.offset > 0 else 0
                limit = req.limit if req.limit > 0 else 1000

                result = self.ida.get_strings(offset=offset, limit=limit)
                resp = pb.GetStringsResponse()
                resp.total = result["total"]
                resp.offset = result["offset"]
                resp.count = result["count"]

                for s in result["strings"]:
                    str_pb = resp.strings.add()
                    str_pb.address = s["address"]
                    str_pb.value = s["value"]
                return resp

            elif method == "MakeFunction":
                req = pb.MakeFunctionRequest()
                req.ParseFromString(proto_body)
                success = self.ida.make_function(req.address)
                resp = pb.MakeFunctionResponse()
                resp.success = success
                return resp

            elif method == "GetDwordAt":
                req = pb.GetDwordAtRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_dword_at(req.address)
                resp = pb.GetDwordAtResponse()
                resp.value = result
                return resp

            elif method == "GetQwordAt":
                req = pb.GetQwordAtRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_qword_at(req.address)
                resp = pb.GetQwordAtResponse()
                resp.value = result
                return resp

            elif method == "GetInstructionLength":
                req = pb.GetInstructionLengthRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_instruction_length(req.address)
                resp = pb.GetInstructionLengthResponse()
                resp.length = result
                return resp

            elif method == "SetComment":
                req = pb.SetCommentRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_comment(req.address, req.comment, req.repeatable)
                resp = pb.SetCommentResponse()
                resp.success = success
                return resp

            elif method == "GetComment":
                req = pb.GetCommentRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_comment(req.address, req.repeatable)
                resp = pb.GetCommentResponse()
                resp.comment = result
                return resp

            elif method == "SetFuncComment":
                req = pb.SetFuncCommentRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_func_comment(req.address, req.comment)
                resp = pb.SetFuncCommentResponse()
                resp.success = success
                return resp

            elif method == "GetFuncComment":
                req = pb.GetFuncCommentRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_func_comment(req.address)
                resp = pb.GetFuncCommentResponse()
                resp.comment = result
                return resp

            elif method == "SetDecompilerComment":
                req = pb.SetDecompilerCommentRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_decompiler_comment(req.function_address, req.address, req.comment)
                resp = pb.SetDecompilerCommentResponse()
                resp.success = success
                return resp

            elif method == "SetName":
                req = pb.SetNameRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_name(req.address, req.name)
                resp = pb.SetNameResponse()
                resp.success = success
                return resp

            elif method == "SetFunctionType":
                req = pb.SetFunctionTypeRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_function_type(req.address, req.prototype)
                resp = pb.SetFunctionTypeResponse()
                resp.success = success
                return resp

            elif method == "SetLvarType":
                req = pb.SetLvarTypeRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_lvar_type(req.function_address, req.lvar_name, req.lvar_type)
                resp = pb.SetLvarTypeResponse()
                resp.success = success
                return resp

            elif method == "RenameLvar":
                req = pb.RenameLvarRequest()
                req.ParseFromString(proto_body)
                success = self.ida.rename_lvar(req.function_address, req.lvar_name, req.new_name)
                resp = pb.RenameLvarResponse()
                resp.success = success
                return resp

            elif method == "GetGlobals":
                req = pb.GetGlobalsRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_globals(req.regex or None, req.case_sensitive)
                resp = pb.GetGlobalsResponse()
                for g in result:
                    glob_pb = resp.globals.add()
                    glob_pb.address = g["address"]
                    glob_pb.name = g["name"]
                    glob_pb.type = g["type"]
                return resp

            elif method == "SetGlobalType":
                req = pb.SetGlobalTypeRequest()
                req.ParseFromString(proto_body)
                success = self.ida.set_global_type(req.address, req.type)
                resp = pb.SetGlobalTypeResponse()
                resp.success = success
                return resp

            elif method == "RenameGlobal":
                req = pb.RenameGlobalRequest()
                req.ParseFromString(proto_body)
                success = self.ida.rename_global(req.address, req.new_name)
                resp = pb.RenameGlobalResponse()
                resp.success = success
                return resp

            elif method == "DataReadString":
                req = pb.DataReadStringRequest()
                req.ParseFromString(proto_body)
                value = self.ida.data_read_string(req.address, req.max_length or 0)
                resp = pb.DataReadStringResponse()
                resp.value = value
                return resp

            elif method == "DataReadByte":
                req = pb.DataReadByteRequest()
                req.ParseFromString(proto_body)
                value = self.ida.data_read_byte(req.address)
                resp = pb.DataReadByteResponse()
                resp.value = value
                return resp

            elif method == "FindBinary":
                req = pb.FindBinaryRequest()
                req.ParseFromString(proto_body)
                matches = self.ida.find_binary(req.start, req.end, req.pattern, req.search_up)
                resp = pb.FindBinaryResponse()
                resp.addresses.extend(matches)
                return resp

            elif method == "FindText":
                req = pb.FindTextRequest()
                req.ParseFromString(proto_body)
                matches = self.ida.find_text(req.start, req.end, req.needle, req.case_sensitive, req.unicode)
                resp = pb.FindTextResponse()
                resp.addresses.extend(matches)
                return resp

            elif method == "ListStructs":
                req = pb.ListStructsRequest()
                req.ParseFromString(proto_body)
                structs = self.ida.list_structs(req.regex, req.case_sensitive)
                resp = pb.ListStructsResponse()
                for item in structs:
                    summary = resp.structs.add()
                    summary.name = item.get("name", "")
                    summary.id = item.get("id", 0)
                    summary.size = item.get("size", 0)
                return resp

            elif method == "GetStruct":
                req = pb.GetStructRequest()
                req.ParseFromString(proto_body)
                struct_info = self.ida.get_struct(req.name)
                resp = pb.GetStructResponse()
                resp.name = struct_info["name"]
                resp.id = struct_info["id"]
                resp.size = struct_info["size"]
                for member in struct_info["members"]:
                    mem = resp.members.add()
                    mem.name = member.get("name", "")
                    mem.offset = member.get("offset", 0)
                    mem.size = member.get("size", 0)
                    mem.type = member.get("type", "")
                return resp

            elif method == "ListEnums":
                req = pb.ListEnumsRequest()
                req.ParseFromString(proto_body)
                enums = self.ida.list_enums(req.regex, req.case_sensitive)
                resp = pb.ListEnumsResponse()
                for item in enums:
                    summary = resp.enums.add()
                    summary.name = item.get("name", "")
                    summary.id = item.get("ordinal", 0)
                return resp

            elif method == "GetEnum":
                req = pb.GetEnumRequest()
                req.ParseFromString(proto_body)
                enum_info = self.ida.get_enum(req.name)
                resp = pb.GetEnumResponse()
                resp.name = enum_info["name"]
                resp.id = enum_info["id"]
                for member in enum_info["members"]:
                    mem = resp.members.add()
                    mem.name = member.get("name", "")
                    mem.value = member.get("value", 0)
                return resp

            elif method == "GetFunctionInfo":
                req = pb.GetFunctionInfoRequest()
                req.ParseFromString(proto_body)
                func_info = self.ida.get_function_info(req.address)
                resp = pb.GetFunctionInfoResponse()
                resp.address = func_info["address"]
                resp.name = func_info["name"]
                resp.start = func_info["start"]
                resp.end = func_info["end"]
                resp.size = func_info["size"]
                resp.frame_size = func_info["frame_size"]
                resp.flags.is_library = func_info["flags"]["is_library"]
                resp.flags.is_thunk = func_info["flags"]["is_thunk"]
                resp.flags.no_return = func_info["flags"]["no_return"]
                resp.flags.has_farseg = func_info["flags"]["has_farseg"]
                resp.flags.is_static = func_info["flags"]["is_static"]
                if func_info["calling_convention"]:
                    resp.calling_convention = func_info["calling_convention"]
                if func_info["return_type"]:
                    resp.return_type = func_info["return_type"]
                resp.num_args = func_info["num_args"]
                return resp

            elif method == "GetTypeAt":
                req = pb.GetTypeAtRequest()
                req.ParseFromString(proto_body)
                type_info = self.ida.get_type_at(req.address)
                resp = pb.GetTypeAtResponse()
                resp.address = type_info["address"]
                resp.type = type_info["type"]
                resp.size = type_info["size"]
                resp.is_ptr = type_info["is_ptr"]
                resp.is_func = type_info["is_func"]
                resp.is_array = type_info["is_array"]
                resp.is_struct = type_info["is_struct"]
                resp.is_union = type_info["is_union"]
                resp.is_enum = type_info["is_enum"]
                resp.has_type = type_info["has_type"]
                return resp

            elif method == "GetName":
                req = pb.GetNameRequest()
                req.ParseFromString(proto_body)
                result = self.ida.get_name(req.address)
                resp = pb.GetNameResponse()
                resp.name = result
                return resp

            elif method == "DeleteName":
                req = pb.DeleteNameRequest()
                req.ParseFromString(proto_body)
                success = self.ida.delete_name(req.address)
                resp = pb.DeleteNameResponse()
                resp.success = success
                return resp

            else:
                raise Exception(f"Unknown method: {method}")

        except Exception as e:
            # Return error in the appropriate response type
            logging.error(f"Analysis tool error: {e}")
            raise

    def _handle_healthcheck(self, method: str, proto_body: bytes):
        """Handle Healthcheck RPC - returns protobuf message"""
        if method == "Ping":
            resp = pb.PingResponse()
            resp.alive = True
            return resp

        elif method == "StatusStream":
            # For now, return single status (streaming would need more work)
            resp = pb.WorkerStatus()
            resp.timestamp = int(time.time())
            resp.memory_bytes = 0  # TODO: implement
            resp.dirty = False
            resp.last_activity = int(self.ida.last_activity)
            resp.pending_requests = self.pending_requests
            return resp

        else:
            raise Exception(f"Unknown method: {method}")

    def _extract_body(self, data: bytes) -> bytes:
        """Extract protobuf body from HTTP request"""
        # Find body after headers
        if b"\r\n\r\n" in data:
            return data.split(b"\r\n\r\n", 1)[1]
        return b""

    def _success_response(self, proto_msg) -> bytes:
        """Build HTTP 200 response with protobuf body"""
        body = proto_msg.SerializeToString()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/proto\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        return response

    def _error_response(self, code: int, message: str) -> bytes:
        """Build HTTP error response"""
        # Use plain text for errors
        body = message.encode()
        status_line = f"HTTP/1.1 {code} Error\r\n".encode()
        response = (
            status_line +
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        return response
