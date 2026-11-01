"""
deobfuscator_engine.ingest
~~~~~~~~~~~~~~~~~~~~~~~~~~
Secure input validation, cryptographic hashing, format detection, and provenance tracking.
Never executes untrusted code during ingestion.
"""

import os
import hashlib
from typing import Dict, Any, Tuple

SUPPORTED_EXTENSIONS = {'.ps1', '.psm1', '.psd1', '.c', '.cpp', '.exe', '.dll', '.txt', '.bin'}

class SecureIngestor:
    """Safely ingests and fingerprints binary executables and script payloads."""

    def __init__(self, max_file_size_mb: float = 25.0):
        self.max_bytes = int(max_file_size_mb * 1024 * 1024)

    def ingest(self, file_path: str) -> Dict[str, Any]:
        """
        Validates file existence, bounds check, computes cryptographic hashes,
        and safely extracts file raw content without execution.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target payload does not exist: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size > self.max_bytes:
            raise ValueError(f"Payload size ({file_size} bytes) exceeds safety ceiling of {self.max_bytes} bytes.")

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()

        safe_name = os.path.basename(file_path.replace("\\", "/"))
        ext = os.path.splitext(safe_name)[1].lower()
        format_type = self._detect_format(raw_bytes, ext)

        # Robust binary inspection: check MZ/ELF magic headers and null byte density
        is_binary = (
            raw_bytes.startswith(b"MZ") or
            raw_bytes.startswith(b"\x7fELF") or
            (b"\x00" in raw_bytes[:1024]) or
            format_type in ["Windows_PE_Binary", "ELF_Binary"]
        )

        text_content = ""
        if not is_binary:
            try:
                text_content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text_content = raw_bytes.decode("latin-1", errors="replace")
        else:
            text_content = f"// Binary Executable ({format_type}): SHA256={sha256}, Size={file_size} bytes"

        return {
            "file_path": os.path.abspath(file_path),
            "file_name": safe_name,
            "file_size": file_size,
            "file_size_bytes": file_size,
            "file_type": format_type,
            "safe_mode": True,
            "sha256": sha256,
            "md5": md5,
            "format": format_type,
            "is_binary": is_binary,
            "raw_bytes_len": len(raw_bytes),
            "text_content": text_content,
            "content": text_content
        }

    def ingest_file(self, file_path: str) -> Dict[str, Any]:
        """Alias for ingest."""
        return self.ingest(file_path)

    def ingest_bytes(self, raw_bytes: bytes, file_name: str = "sample.ps1") -> Dict[str, Any]:
        """Safely ingests in-memory raw bytes with sanitization against path traversal."""
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()
        
        # Sanitize against path traversal
        safe_name = os.path.basename(file_name.replace("\\", "/"))
        if not safe_name:
            safe_name = "sample.ps1"

        ext = os.path.splitext(safe_name)[1].lower()
        format_type = self._detect_format(raw_bytes, ext)

        # Robust binary inspection: check MZ/ELF magic headers and null byte density
        is_binary = (
            raw_bytes.startswith(b"MZ") or
            raw_bytes.startswith(b"\x7fELF") or
            (b"\x00" in raw_bytes[:1024]) or
            format_type in ["Windows_PE_Binary", "ELF_Binary"]
        )

        text_content = ""
        if not is_binary:
            try:
                text_content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text_content = raw_bytes.decode("latin-1", errors="replace")
        else:
            text_content = f"// Binary Executable ({format_type}): SHA256={sha256}, Size={len(raw_bytes)} bytes"

        return {
            "file_path": "memory://" + safe_name,
            "file_name": safe_name,
            "file_size": len(raw_bytes),
            "file_size_bytes": len(raw_bytes),
            "file_type": format_type,
            "safe_mode": True,
            "sha256": sha256,
            "md5": md5,
            "format": format_type,
            "is_binary": is_binary,
            "raw_bytes_len": len(raw_bytes),
            "text_content": text_content,
            "content": text_content
        }

    def _detect_format(self, raw_bytes: bytes, ext: str) -> str:
        if raw_bytes.startswith(b"MZ"):
            return "Windows_PE_Binary"
        if ext in {".ps1", ".psm1", ".psd1"}:
            return "PowerShell_Script"
        if ext in {".c", ".cpp", ".h"}:
            return "C_Pseudocode"
        if ext in {".txt", ".log"}:
            return "Text_Payload"
        return "Generic_Payload"

# Alias for backwards compatibility
Ingestor = SecureIngestor
