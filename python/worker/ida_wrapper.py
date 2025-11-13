"""
IDA Library Wrapper
Handles idalib initialization and provides safe API access
"""

import json
import logging
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

import idapro


class IDAWrapper:
    """Wrapper around idalib with error handling"""

    def __init__(self, binary_path: str, session_id: str):
        self.binary_path = binary_path
        self.session_id = session_id
        self.db_open = False
        self.has_decompiler = False
        self.opened_at = None
        self.last_activity = None
        self.last_error: str | None = None

        # IDA modules (available after database opens)
        self.ida_auto = None
        self.ida_funcs = None
        self.ida_name = None
        self.ida_bytes = None
        self.ida_segment = None
        self.idautils = None
        self.idc = None
        self.ida_hexrays = None
        self.ida_ua = None
        self.idaapi = None
        self.ida_nalt = None
        self.analysis_state = "not_started"

    def open_database(self, auto_analyze: bool = False) -> bool:
        """Open IDA database"""
        self.last_error = None
        try:
            import os

            # Check if binary file exists
            if not os.path.exists(self.binary_path):
                msg = f"Binary file not found: {self.binary_path}"
                logging.error(msg)
                self.last_error = msg
                return False

            # Disable console messages
            idapro.enable_console_messages(False)

            # Open database with compression
            result = idapro.open_database(self.binary_path, auto_analyze, "-P+")

            if result != 0:
                error_msgs = {
                    -1: "File not found or cannot be opened",
                    1: "Database format error",
                    2: "Architecture not supported",
                    4: "Database already exists or corrupted"
                }
                error_msg = error_msgs.get(result, f'Error code {result}')
                logging.warning(f"Database open failed: {error_msg}")
                self.last_error = error_msg

                # Try to repair corrupted database (error codes 1 and 4)
                if result in [1, 4]:
                    logging.info("Attempting to repair database by deleting and recreating...")
                    import os
                    import glob

                    # Find and delete all IDA database files for this binary
                    base_path = os.path.splitext(self.binary_path)[0]
                    patterns = [
                        f"{base_path}.i64",
                        f"{base_path}.idb",
                        f"{base_path}.id0",
                        f"{base_path}.id1",
                        f"{base_path}.id2",
                        f"{base_path}.nam",
                        f"{base_path}.til"
                    ]

                    deleted_files = []
                    for pattern in patterns:
                        for filepath in glob.glob(pattern):
                            try:
                                os.remove(filepath)
                                deleted_files.append(filepath)
                                logging.info(f"Deleted corrupted database file: {filepath}")
                            except Exception as e:
                                logging.warning(f"Could not delete {filepath}: {e}")

                    # Retry opening with fresh database (whether files were deleted or not)
                    if deleted_files:
                        logging.info(f"Deleted {len(deleted_files)} database files, retrying with fresh analysis...")
                    else:
                        logging.info("No existing database files found, creating fresh database...")

                    result = idapro.open_database(self.binary_path, True, "-P+")

                    if result != 0:
                        final_error = error_msgs.get(result, f'Error code {result}')
                        logging.error(f"Database creation failed: {final_error}")
                        self.last_error = final_error
                        return False
                else:
                    logging.error(f"Failed to open database: {error_msg}")
                    self.last_error = error_msg
                    return False

            # NOW import IDA modules
            import ida_auto
            import ida_funcs
            import ida_name
            import ida_bytes
            import ida_segment
            import idautils
            import idc
            import ida_ua
            import idaapi
            import ida_typeinf
            import ida_nalt

            self.ida_auto = ida_auto
            self.ida_funcs = ida_funcs
            self.ida_name = ida_name
            self.ida_bytes = ida_bytes
            self.ida_segment = ida_segment
            self.idautils = idautils
            self.idc = idc
            self.ida_ua = ida_ua
            self.idaapi = idaapi
            self.ida_typeinf = ida_typeinf
            self.ida_nalt = ida_nalt

            # Try to load decompiler
            try:
                import ida_hexrays
                self.ida_hexrays = ida_hexrays
                self.has_decompiler = ida_hexrays.init_hexrays_plugin()
            except:
                self.has_decompiler = False

            self.db_open = True
            self.opened_at = time.time()
            self.last_activity = time.time()

            logging.info(f"Database opened (decompiler: {self.has_decompiler})")
            self.last_error = None
            self.analysis_state = "idle"
            return True

        except Exception as e:
            message = f"Exception opening database: {e}"
            logging.error(message)
            self.last_error = message
            return False

    def save_database(self) -> tuple[bool, int, bool]:
        """
        Save IDA database
        Returns: (success, timestamp, dirty)
        """
        try:
            if not self.db_open:
                return (False, 0, False)

            # Check if database has unsaved changes
            dirty = self.idaapi.is_database_flag(self.idaapi.DBFL_KILL)

            # Save database via idaapi (idapro.save_database unavailable in some builds)
            result = self.idaapi.save_database("", 0)

            if result:
                timestamp = int(time.time())
                logging.info(f"Database saved (dirty: {dirty})")
                return (True, timestamp, dirty)
            else:
                logging.error("Database save failed")
                return (False, 0, dirty)

        except Exception as e:
            logging.error(f"Exception saving database: {e}")
            return (False, 0, False)

    def close_database(self, save: bool = True) -> bool:
        """Close IDA database"""
        try:
            if save:
                # Try to save first
                success, _, _ = self.save_database()
                if not success:
                    logging.warning("Failed to save database before closing")

            idapro.close_database(save)
            self.db_open = False
            logging.info(f"Database closed (saved: {save})")
            return True
        except Exception as e:
            logging.error(f"Error closing database: {e}")
            return False

    def touch(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()

    def get_auto_status(self) -> tuple[bool, str]:
        """Return (is_auto_running, state_name) from ida_auto if available"""
        if not self.db_open or self.ida_auto is None:
            return (False, "database_closed")

        running = False
        try:
            running = bool(self.ida_auto.is_auto_running())
        except Exception as e:
            logging.debug(f"Failed to query ida_auto.is_auto_running: {e}")

        state = self._resolve_auto_state()
        if running:
            self.analysis_state = state or "running"
        elif state:
            self.analysis_state = state
        return (running, state or ("running" if running else "idle"))

    def _resolve_auto_state(self) -> str:
        """Best-effort string description of IDA auto-analysis state."""
        if self.ida_auto is None:
            return "unknown"

        state_sources = [
            "get_auto_state_name",
            "get_status_name",
            "state_name",
            "auto_state",
            "get_auto_state",
            "get_status",
        ]

        for attr in state_sources:
            member = getattr(self.ida_auto, attr, None)
            if member is None:
                continue
            try:
                if callable(member):
                    value = member()
                else:
                    value = member
                if value is None:
                    continue
                return str(value)
            except Exception:
                continue

        return self.analysis_state or "unknown"

    def plan_and_wait(self) -> tuple[bool, float, str | None]:
        """Run IDA auto-analysis to completion."""
        if not self.db_open or self.ida_auto is None:
            return (False, 0.0, "database not open")
        try:
            import time

            start = time.time()
            self.ida_auto.auto_wait()
            duration = time.time() - start
            self.last_activity = time.time()
            self.analysis_state = "idle"
            return (True, duration, None)
        except Exception as exc:
            return (False, 0.0, str(exc))

    def import_il2cpp(self, script_json: str, il2cpp_header: str, fields: list[str] | None = None) -> dict:
        """Import Il2CppDumper metadata into the current database."""
        if not self.db_open:
            raise RuntimeError("IDA database is not open. Call OpenBinary first.")
        self.touch()
        start = time.time()

        if not script_json:
            raise ValueError("script_json is required")
        if not il2cpp_header:
            raise ValueError("il2cpp header is required")

        try:
            metadata = json.loads(script_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid script_json: {exc}") from exc

        enabled = set(fields or [
            "Addresses",
            "ScriptMethod",
            "ScriptString",
            "ScriptMetadata",
            "ScriptMetadataMethod",
        ])

        header_applied = False
        header_error = None
        try:
            parse_result = self.idaapi.parse_decls(il2cpp_header, 0)
            header_applied = bool(parse_result)
        except Exception as exc:
            header_error = str(exc)
            logging.warning("Failed to parse il2cpp.h declarations: %s", exc)

        image_base = self.idaapi.get_imagebase()
        stats = {
            "functions_defined": 0,
            "functions_named": 0,
            "strings_named": 0,
            "metadata_named": 0,
            "metadata_methods": 0,
            "signatures_applied": 0,
            "header_applied": header_applied,
        }

        def abs_addr(value):
            if value is None:
                return None
            return image_base + int(value)

        def set_unique_name(addr, name):
            flags = getattr(self.idc, "SN_NOWARN", 0) | getattr(self.idc, "SN_NOCHECK", 0)
            if not self.idc.set_name(addr, name, flags):
                fallback = f"{name}_{addr:x}"
                self.idc.set_name(addr, fallback, flags)

        if "Addresses" in enabled and isinstance(metadata.get("Addresses"), list):
            addresses = metadata["Addresses"]
            for idx in range(len(addresses) - 1):
                start_ea = abs_addr(addresses[idx])
                end_ea = abs_addr(addresses[idx + 1])
                if start_ea is None or end_ea is None or start_ea >= end_ea:
                    continue
                next_func = self.idc.get_next_func(start_ea)
                if next_func != self.idc.BADADDR and next_func < end_ea:
                    end_ea = next_func
                existing = self.ida_funcs.get_func(start_ea)
                if existing:
                    self.ida_funcs.del_func(start_ea)
                if self.ida_funcs.add_func(start_ea, end_ea):
                    stats["functions_defined"] += 1

        parse_decl_fn = getattr(self.idc, "parse_decl", None)
        apply_type_fn = getattr(self.idc, "apply_type", None)

        if "ScriptMethod" in enabled and isinstance(metadata.get("ScriptMethod"), list):
            for item in metadata["ScriptMethod"]:
                addr = abs_addr(item.get("Address"))
                name = item.get("Name")
                if addr is None or not name:
                    continue
                set_unique_name(addr, name)
                stats["functions_named"] += 1
                signature = item.get("Signature")
                if signature and apply_type_fn and parse_decl_fn:
                    try:
                        decl = parse_decl_fn(signature, 0)
                        if decl and apply_type_fn(addr, decl, 1):
                            stats["signatures_applied"] += 1
                    except Exception as exc:
                        logging.debug("Failed to apply signature %s at %x: %s", signature, addr, exc)

        if "ScriptString" in enabled and isinstance(metadata.get("ScriptString"), list):
            for idx, item in enumerate(metadata["ScriptString"], start=1):
                addr = abs_addr(item.get("Address"))
                if addr is None:
                    continue
                set_unique_name(addr, f"StringLiteral_{idx}")
                value = item.get("Value") or ""
                self.idc.set_cmt(addr, value, 1)
                stats["strings_named"] += 1

        if "ScriptMetadata" in enabled and isinstance(metadata.get("ScriptMetadata"), list):
            for item in metadata["ScriptMetadata"]:
                addr = abs_addr(item.get("Address"))
                name = item.get("Name")
                if addr is None or not name:
                    continue
                set_unique_name(addr, name)
                self.idc.set_cmt(addr, name, 1)
                stats["metadata_named"] += 1

        if "ScriptMetadataMethod" in enabled and isinstance(metadata.get("ScriptMetadataMethod"), list):
            for item in metadata["ScriptMetadataMethod"]:
                addr = abs_addr(item.get("Address"))
                method_addr = abs_addr(item.get("MethodAddress"))
                name = item.get("Name")
                if addr is None or not name:
                    continue
                set_unique_name(addr, name)
                self.idc.set_cmt(addr, name, 1)
                if method_addr is not None:
                    self.idc.set_cmt(addr, f"{method_addr:X}", 0)
                stats["metadata_methods"] += 1

        stats["duration_seconds"] = time.time() - start
        if header_error:
            stats["header_error"] = header_error
        return stats

    # Analysis operations

    def get_bytes(self, address: int, size: int) -> bytes:
        """Read bytes at address"""
        self.touch()

        # Validate inputs
        if size <= 0:
            raise ValueError("Size must be positive")
        if size > 10 * 1024 * 1024:  # 10MB limit to prevent DoS
            raise ValueError("Size too large (max 10MB)")

        # Validate address is in a valid segment
        seg = self.ida_segment.getseg(address)
        if not seg:
            raise ValueError(f"Address {hex(address)} not in valid segment")

        try:
            data = bytes([self.ida_bytes.get_byte(address + i) for i in range(size)])
            return data
        except Exception as e:
            raise Exception(f"Error reading bytes: {e}")

    def get_disasm(self, address: int) -> str:
        """Get disassembly at address"""
        self.touch()
        return self.idc.generate_disasm_line(address, 0)

    def get_function_disasm(self, address: int) -> str:
        """Get complete disassembly for a function"""
        self.touch()
        func = self.ida_funcs.get_func(address)
        if not func:
            raise ValueError(f"No function at address {hex(address)}")
        lines = []
        for ea in self.idautils.FuncItems(func.start_ea):
            line = self.idc.generate_disasm_line(ea, 0) or ""
            lines.append(f"{ea:08X}: {line}")
        return "\n".join(lines)

    def get_decompiled(self, address: int) -> str:
        """Get decompiled pseudocode"""
        self.touch()
        if not self.has_decompiler:
            raise Exception("Decompiler not available (Hex-Rays not installed or not licensed)")

        func = self.ida_funcs.get_func(address)
        if not func:
            raise Exception(f"No function at address {hex(address)}")

        try:
            decompiler = self.ida_hexrays.decompile(func.start_ea)
            if not decompiler:
                raise Exception("Failed to decompile function")
            return str(decompiler)
        except Exception as e:
            # Check for common Hex-Rays errors
            if "HexRaysError" in str(type(e).__name__):
                raise Exception(f"Decompilation failed: {e}")
            raise

    def get_function_name(self, address: int) -> str:
        """Get function name at address"""
        self.touch()
        return self.ida_name.get_name(address)

    def get_segments(self) -> list:
        """Get all segments"""
        self.touch()
        segments = []
        n = 0
        seg = self.ida_segment.getnseg(n)
        while seg:
            segments.append({
                "start": seg.start_ea,
                "end": seg.end_ea,
                "name": self.ida_segment.get_segm_name(seg),
                "seg_class": self.ida_segment.get_segm_class(seg),
                "permissions": seg.perm,
                "bitness": seg.bitness
            })
            n += 1
            seg = self.ida_segment.getnseg(n)
        return segments

    def get_functions(self) -> list:
        """Get all functions"""
        self.touch()
        functions = []
        for func_ea in self.idautils.Functions():
            func_name = self.ida_name.get_name(func_ea)
            functions.append({"address": func_ea, "name": func_name})
        return functions

    def get_xrefs_to(self, address: int) -> list:
        """Get cross-references to address"""
        self.touch()
        xrefs = []
        for xref in self.idautils.XrefsTo(address, 0):
            xrefs.append({"from": xref.frm, "to": address, "type": xref.type})
        return xrefs

    def get_xrefs_from(self, address: int) -> list:
        """Get cross-references originating from address"""
        self.touch()
        xrefs = []
        for xref in self.idautils.XrefsFrom(address, 0):
            xrefs.append({"from": address, "to": xref.to, "type": xref.type})
        return xrefs

    def get_data_refs(self, address: int) -> list:
        """Get data references to address"""
        self.touch()
        refs = []
        import ida_xref

        xb = ida_xref.xrefblk_t()
        if xb.first_to(address, ida_xref.XREF_DATA):
            while True:
                refs.append({"from": xb.frm, "type": xb.type})
                if not xb.next_to():
                    break
        return refs

    def get_string_xrefs(self, address: int) -> list:
        """Get string references (with function context)"""
        self.touch()
        refs = []
        import ida_xref

        xb = ida_xref.xrefblk_t()
        if xb.first_to(address, ida_xref.XREF_ALL):
            while True:
                func = self.ida_funcs.get_func(xb.frm)
                func_addr = func.start_ea if func else 0
                func_name = self.ida_name.get_name(func_addr) if func_addr else ""
                refs.append({
                    "address": xb.frm,
                    "function_address": func_addr,
                    "function_name": func_name,
                })
                if not xb.next_to():
                    break
        return refs

    def get_imports(self) -> list:
        """Get imports"""
        self.touch()
        imports = []
        nimps = self.idaapi.get_import_module_qty()

        for i in range(0, nimps):
            module = self.idaapi.get_import_module_name(i)
            if not module:
                continue

            def callback(ea, name, ord):
                imports.append({
                    "module": module,
                    "address": ea,
                    "name": name or "",
                    "ordinal": ord
                })
                return True

            self.idaapi.enum_import_names(i, callback)

        return imports

    def get_exports(self) -> list:
        """Get exports"""
        self.touch()
        exports = []
        for entry in self.idautils.Entries():
            exports.append({
                "index": entry[0],
                "ordinal": entry[1],
                "address": entry[2],
                "name": entry[3]
            })
        return exports

    def get_entry_point(self) -> int:
        """Get entry point"""
        self.touch()
        try:
            import ida_ida
            return ida_ida.inf_get_start_ea()
        except (ImportError, AttributeError):
            try:
                return self.idc.get_inf_attr(self.idc.INF_START_EA)
            except:
                return self.idaapi.cvar.inf.start_ea

    def get_strings(self, offset: int = 0, limit: int = 1000, regex: str = None, case_sensitive: bool = False) -> dict:
        """Get strings with pagination and optional regex filtering"""
        self.touch()

        import re
        all_strings = list(self.idautils.Strings())
        pattern = None
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(regex, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex: {e}")

        filtered = []
        for s in all_strings:
            value = str(s)
            if pattern and not pattern.search(value):
                continue
            filtered.append({"address": s.ea, "value": value})

        total = len(filtered)
        start = max(0, offset)
        end = start + limit if limit > 0 else total
        paginated = filtered[start:end]

        return {
            "total": total,
            "offset": start,
            "count": len(paginated),
            "limit": limit,
            "strings": paginated
        }

    def make_function(self, address: int) -> bool:
        """Create function at address"""
        self.touch()
        return self.ida_funcs.add_func(address) != 0

    def get_dword_at(self, address: int) -> int:
        """Read 32-bit value"""
        self.touch()
        return self.ida_bytes.get_dword(address)

    def get_qword_at(self, address: int) -> int:
        """Read 64-bit value"""
        self.touch()
        return self.ida_bytes.get_qword(address)

    def get_instruction_length(self, address: int) -> int:
        """Get instruction length"""
        self.touch()
        insn = self.ida_ua.insn_t()
        length = self.ida_ua.decode_insn(insn, address)
        if length == 0:
            raise Exception(f"Failed to decode instruction at {hex(address)}")
        return length

    # Annotation operations

    def set_comment(self, address: int, comment: str, repeatable: bool = False) -> bool:
        """Set comment at address"""
        self.touch()
        return self.idc.set_cmt(address, comment, repeatable)

    def get_comment(self, address: int, repeatable: bool = False) -> str:
        """Get comment at address"""
        self.touch()
        result = self.idc.get_cmt(address, repeatable)
        return result if result else ""

    def set_func_comment(self, address: int, comment: str) -> bool:
        """Set function comment"""
        self.touch()
        return self.idc.set_func_cmt(address, comment, False)

    def get_func_comment(self, address: int) -> str:
        """Get function comment"""
        self.touch()
        result = self.idc.get_func_cmt(address, False)
        return result if result else ""

    def set_name(self, address: int, name: str) -> bool:
        """Set name at address"""
        self.touch()
        # idc.set_name returns 1 on success, 0 on failure
        return self.idc.set_name(address, name, 0) != 0

    def get_name(self, address: int) -> str:
        """Get name at address"""
        self.touch()
        result = self.idc.get_name(address)
        return result if result else ""

    def set_function_type(self, address: int, prototype: str) -> bool:
        """Apply a C-style prototype to a function"""
        self.touch()
        if not prototype:
            raise ValueError("prototype is required")
        parse_decl = getattr(self.idc, "parse_decl", None)
        apply_type = getattr(self.idc, "apply_type", None)
        if not parse_decl or not apply_type:
            raise RuntimeError("IDA does not expose parse_decl/apply_type in this environment")
        try:
            decl = parse_decl(prototype, 0)
        except Exception as exc:
            raise ValueError(f"failed to parse prototype: {exc}") from exc
        if not decl:
            raise ValueError("prototype parse returned empty result")
        try:
            success = apply_type(address, decl, 1)
        except Exception as exc:
            raise RuntimeError(f"failed to apply prototype: {exc}") from exc
        if not success:
            raise RuntimeError("IDA apply_type returned failure")
        return True

    def delete_name(self, address: int) -> bool:
        """Delete name at address"""
        self.touch()
        # idc.del_name returns 1 on success, 0 on failure
        return self.idc.del_name(address) != 0

    def _require_hexrays(self):
        if not self.has_decompiler or self.ida_hexrays is None:
            raise RuntimeError("Decompiler not available (Hex-Rays not installed or licensed)")

    def _resolve_lvar(self, cfunc, lvar_name: str):
        for lvar in cfunc.get_lvars():
            if lvar.name == lvar_name:
                return lvar
        raise ValueError(f"Local variable '{lvar_name}' not found")

    def set_lvar_type(self, func_ea: int, lvar_name: str, prototype: str) -> bool:
        """Apply a C-style type to a local variable."""
        self.touch()
        self._require_hexrays()
        if not prototype:
            raise ValueError("Prototype must be provided")
        cfunc = self.ida_hexrays.decompile(func_ea)
        if not cfunc:
            raise RuntimeError("Failed to decompile function")
        target = self._resolve_lvar(cfunc, lvar_name)
        tinfo = self.ida_typeinf.tinfo_t()
        # parse_decl expects a full declaration like "__int64 var", so combine type with variable name
        full_decl = f"{prototype} {lvar_name};"
        if not self.ida_typeinf.parse_decl(tinfo, None, full_decl, self.ida_typeinf.PT_VAR):
            raise ValueError(f"Failed to parse type declaration: {full_decl}")

        # Use modify_user_lvar_info (headless-compatible API)
        lvar_info = self.ida_hexrays.lvar_saved_info_t()
        lvar_info.ll = target
        lvar_info.type = tinfo
        if not self.ida_hexrays.modify_user_lvar_info(func_ea, self.ida_hexrays.MLI_TYPE, lvar_info):
            raise RuntimeError("Failed to modify local variable type")
        return True

    def rename_lvar(self, func_ea: int, lvar_name: str, new_name: str) -> bool:
        """Rename a Hex-Rays local variable."""
        self.touch()
        self._require_hexrays()
        if not new_name:
            raise ValueError("New name must be provided")
        cfunc = self.ida_hexrays.decompile(func_ea)
        if not cfunc:
            raise RuntimeError("Failed to decompile function")
        target = self._resolve_lvar(cfunc, lvar_name)

        # Use modify_user_lvar_info (headless-compatible API)
        lvar_info = self.ida_hexrays.lvar_saved_info_t()
        lvar_info.ll = target
        lvar_info.name = new_name
        if not self.ida_hexrays.modify_user_lvar_info(func_ea, self.ida_hexrays.MLI_NAME, lvar_info):
            raise RuntimeError("Failed to rename local variable")
        return True

    def set_decompiler_comment(self, func_ea: int, address: int, comment: str) -> bool:
        """Attach a Hex-Rays pseudocode comment."""
        self.touch()
        self._require_hexrays()
        if not comment:
            raise ValueError("comment is required")
        cfunc = self.ida_hexrays.decompile(func_ea)
        if not cfunc:
            raise RuntimeError("Failed to decompile function")

        # Create treeloc_t for the address
        treeloc = self.ida_hexrays.treeloc_t()
        treeloc.ea = address

        # Set the comment at this location
        cfunc.set_user_cmt(treeloc, comment)

        # Save comments and refresh
        cfunc.save_user_cmts()
        return True

    def get_globals(self, regex: str | None = None, case_sensitive: bool = False) -> list:
        """Enumerate globals with optional regex filtering."""
        self.touch()
        import ida_bytes
        import ida_segment

        compiled = None
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(regex, flags)

        globals_list = []
        for seg_ea in self.idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            seg_class = ida_segment.get_segm_class(seg)
            if seg_class not in {"DATA", "BSS"}:
                continue
            ea = seg.start_ea
            while ea < seg.end_ea:
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_data(flags):
                    name = self.ida_name.get_name(ea)
                    if name:
                        if compiled and not compiled.search(name):
                            ea = ida_bytes.next_not_tail(ea)
                            continue
                        gtype = self.idc.get_type(ea) or ""
                        globals_list.append({
                            "address": ea,
                            "name": name,
                            "type": gtype,
                        })
                ea = ida_bytes.next_not_tail(ea)
        return globals_list

    def set_global_type(self, address: int, type_decl: str) -> bool:
        """Apply a type to a global variable."""
        self.touch()
        if not type_decl:
            raise ValueError("type is required")

        # Get the current name at this address
        name = self.ida_name.get_name(address)
        if not name:
            name = f"var_{address:X}"

        # Construct full declaration with name and semicolon
        full_decl = f"{type_decl} {name};"
        tinfo = self.ida_typeinf.tinfo_t()
        if not self.ida_typeinf.parse_decl(tinfo, None, full_decl, self.ida_typeinf.PT_VAR):
            raise ValueError(f"Failed to parse type: {full_decl}")
        if not self.ida_typeinf.apply_tinfo(address, tinfo, self.ida_typeinf.TINFO_DEFINITE):
            raise RuntimeError("IDA rejected the type")
        return True

    def rename_global(self, address: int, new_name: str) -> bool:
        """Rename global variable."""
        self.touch()
        if not new_name:
            raise ValueError("new_name is required")
        return self.idc.set_name(address, new_name, self.idc.SN_NOWARN) != 0

    def data_read_string(self, address: int, max_length: int = 256) -> str:
        """Read ASCII string from memory."""
        self.touch()
        if max_length <= 0:
            max_length = 256
        # Read bytes until null terminator or max_length
        data = self.ida_bytes.get_bytes(address, max_length)
        if data is None:
            return ""
        # Find null terminator
        null_pos = data.find(b'\x00')
        if null_pos >= 0:
            data = data[:null_pos]
        return data.decode('utf-8', errors='replace')

    def data_read_byte(self, address: int) -> int:
        """Read a single byte."""
        self.touch()
        import ida_bytes
        value = ida_bytes.get_byte(address)
        if value is None:
            raise ValueError("Invalid address")
        return value

    def find_binary(self, start: int, end: int, pattern: str, search_up: bool = False) -> list:
        """Find binary pattern occurrences."""
        self.touch()
        import ida_bytes
        if not pattern:
            raise ValueError("pattern is required")
        if start == 0:
            start = self.idaapi.get_imagebase()
        if end == 0:
            end = self.idaapi.BADADDR

        # Compile the pattern string into binary pattern format
        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        encoding_error = ida_bytes.parse_binpat_str(compiled_pattern, start, pattern, 16)
        if encoding_error:
            raise ValueError(f"Invalid binary pattern: {pattern}")

        ea = start
        results = []
        visited = set()
        direction = ida_bytes.BIN_SEARCH_BACKWARD if search_up else ida_bytes.BIN_SEARCH_FORWARD

        while True:
            # bin_search returns (ea, size) tuple
            result = ida_bytes.bin_search(ea, end, compiled_pattern, direction)
            next_ea = result[0] if isinstance(result, tuple) else result
            if next_ea == self.idaapi.BADADDR or next_ea in visited:
                break
            results.append(next_ea)
            visited.add(next_ea)
            ea = next_ea - 1 if search_up else next_ea + 1
        return results

    def find_text(self, start: int, end: int, text: str, case_sensitive: bool, unicode: bool) -> list:
        """Find ASCII/UTF-8 strings."""
        self.touch()
        import ida_search
        if not text:
            raise ValueError("text is required")
        if start == 0:
            start = self.idaapi.get_imagebase()
        if end == 0:
            end = self.idaapi.BADADDR

        # Prepare search text
        search_text = text if case_sensitive else text.lower()

        ea = start
        results = []
        visited = set()
        flags = ida_search.SEARCH_DOWN
        if case_sensitive:
            flags |= ida_search.SEARCH_CASE

        while True:
            # Use find_text with proper signature: find_text(ea, y, x, needle, flags)
            next_ea = ida_search.find_text(ea, 0, 0, search_text, flags)
            if next_ea == self.idaapi.BADADDR or next_ea in visited:
                break
            if end != self.idaapi.BADADDR and next_ea >= end:
                break
            results.append(next_ea)
            visited.add(next_ea)
            ea = next_ea + len(search_text)
        return results

    def list_structs(self, regex: str | None = None, case_sensitive: bool = False) -> list:
        """Enumerate IDA structures with optional filtering."""
        self.touch()
        compiled = None
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(regex, flags)
        structs = []

        # Iterate through type ordinals to find structures
        ti = self.ida_typeinf.get_idati()
        for ordinal in range(1, self.ida_typeinf.get_ordinal_limit(ti)):
            tinfo = self.ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(ti, ordinal):
                if tinfo.is_struct() or tinfo.is_union():
                    name = tinfo.get_type_name()
                    if name and (not compiled or compiled.search(name)):
                        size = tinfo.get_size()
                        structs.append({"name": name, "ordinal": ordinal, "size": size})
        return structs

    def get_struct(self, name: str) -> dict:
        """Return structure metadata including members."""
        self.touch()
        if not name:
            raise ValueError("name is required")

        # Find the structure by name in type ordinals
        tinfo = self.ida_typeinf.tinfo_t()
        ti = self.ida_typeinf.get_idati()
        if not tinfo.get_named_type(ti, name):
            raise ValueError(f"Structure {name} not found")

        if not (tinfo.is_struct() or tinfo.is_union()):
            raise ValueError(f"{name} is not a structure or union")

        # Get ordinal for this type (use as id)
        ordinal = tinfo.get_ordinal()
        if ordinal == 0:
            ordinal = 1  # Default if ordinal not found

        # Extract members using UDT (user-defined type) API
        members = []
        udt_data = self.ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt_data):
            for i in range(udt_data.size()):
                member = udt_data[i]
                mem_name = member.name
                mem_offset = member.offset // 8  # Convert bits to bytes
                mem_size = member.size // 8
                mem_type = member.type.dstr()
                members.append({
                    "name": mem_name,
                    "offset": mem_offset,
                    "size": mem_size,
                    "type": mem_type,
                })

        return {
            "name": name,
            "id": ordinal,
            "size": tinfo.get_size(),
            "is_union": tinfo.is_union(),
            "members": members
        }

    def list_enums(self, regex: str | None = None, case_sensitive: bool = False) -> list:
        """Enumerate IDA enumerations with optional filtering."""
        self.touch()
        compiled = None
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(regex, flags)
        enums = []

        # Iterate through type ordinals to find enums
        ti = self.ida_typeinf.get_idati()
        for ordinal in range(1, self.ida_typeinf.get_ordinal_limit(ti)):
            tinfo = self.ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(ti, ordinal):
                if tinfo.is_enum():
                    name = tinfo.get_type_name()
                    if name and (not compiled or compiled.search(name)):
                        enums.append({"name": name, "ordinal": ordinal})
        return enums

    def get_enum(self, name: str) -> dict:
        """Return enumeration metadata including members."""
        self.touch()
        if not name:
            raise ValueError("name is required")

        # Find the enum by name in type ordinals
        tinfo = self.ida_typeinf.tinfo_t()
        ti = self.ida_typeinf.get_idati()
        if not tinfo.get_named_type(ti, name):
            raise ValueError(f"Enum {name} not found")

        if not tinfo.is_enum():
            raise ValueError(f"{name} is not an enumeration")

        # Get ordinal for this type (use as id)
        ordinal = tinfo.get_ordinal()
        if ordinal == 0:
            ordinal = 1

        # Extract enum members
        members = []
        enum_data = self.ida_typeinf.enum_type_data_t()
        if tinfo.get_enum_details(enum_data):
            for i in range(enum_data.size()):
                member = enum_data[i]
                members.append({
                    "name": member.name,
                    "value": member.value,
                })

        return {
            "name": name,
            "id": ordinal,
            "members": members
        }

    def get_type_at(self, address: int) -> dict:
        """Get type information at address."""
        self.touch()
        tinfo = self.ida_typeinf.tinfo_t()

        # Try to get type information at this address
        # In IDA Python, get_tinfo is in ida_nalt module
        if self.ida_nalt.get_tinfo(tinfo, address):
            type_str = tinfo.dstr()
            size = tinfo.get_size()
            is_ptr = tinfo.is_ptr()
            is_func = tinfo.is_func()
            is_array = tinfo.is_array()
            is_struct = tinfo.is_struct()
            is_union = tinfo.is_union()
            is_enum = tinfo.is_enum()

            return {
                "address": address,
                "type": type_str,
                "size": size,
                "is_ptr": is_ptr,
                "is_func": is_func,
                "is_array": is_array,
                "is_struct": is_struct,
                "is_union": is_union,
                "is_enum": is_enum,
                "has_type": True,
            }
        else:
            # No type information available
            return {
                "address": address,
                "type": "",
                "size": 0,
                "is_ptr": False,
                "is_func": False,
                "is_array": False,
                "is_struct": False,
                "is_union": False,
                "is_enum": False,
                "has_type": False,
            }

    def get_function_info(self, address: int) -> dict:
        """Get comprehensive function metadata including bounds, flags, and calling convention."""
        self.touch()
        func = self.ida_funcs.get_func(address)
        if not func:
            raise ValueError(f"No function at address 0x{address:X}")

        # Get function bounds
        start_ea = func.start_ea
        end_ea = func.end_ea
        size = end_ea - start_ea

        # Get function name
        name = self.ida_funcs.get_func_name(start_ea) or f"sub_{start_ea:X}"

        # Get function flags
        flags = func.flags
        is_library = bool(flags & self.ida_funcs.FUNC_LIB)
        is_thunk = bool(flags & self.ida_funcs.FUNC_THUNK)
        no_return = bool(flags & self.ida_funcs.FUNC_NORET)
        has_farseg = bool(flags & self.ida_funcs.FUNC_FAR)
        is_static = bool(flags & self.ida_funcs.FUNC_STATICDEF)

        # Get frame size
        frame_size = func.frsize if hasattr(func, 'frsize') else 0

        # Try to get calling convention and type from decompiler
        calling_convention = None
        return_type = None
        num_args = 0

        if self.has_decompiler:
            try:
                # Get function type info
                tinfo = self.ida_typeinf.tinfo_t()
                if self.ida_nalt.get_tinfo(tinfo, start_ea):
                    # Get calling convention
                    cc = tinfo.get_cc()
                    if cc == self.ida_typeinf.CM_CC_CDECL:
                        calling_convention = "cdecl"
                    elif cc == self.ida_typeinf.CM_CC_STDCALL:
                        calling_convention = "stdcall"
                    elif cc == self.ida_typeinf.CM_CC_FASTCALL:
                        calling_convention = "fastcall"
                    elif cc == self.ida_typeinf.CM_CC_THISCALL:
                        calling_convention = "thiscall"
                    else:
                        calling_convention = f"unknown({cc})"

                    # Get return type
                    rettype = tinfo.get_rettype()
                    if rettype:
                        return_type = rettype.dstr()

                    # Get number of arguments
                    num_args = tinfo.get_nargs()
            except:
                pass

        return {
            "address": start_ea,
            "name": name,
            "start": start_ea,
            "end": end_ea,
            "size": size,
            "frame_size": frame_size,
            "flags": {
                "is_library": is_library,
                "is_thunk": is_thunk,
                "no_return": no_return,
                "has_farseg": has_farseg,
                "is_static": is_static,
            },
            "calling_convention": calling_convention,
            "return_type": return_type,
            "num_args": num_args,
        }
