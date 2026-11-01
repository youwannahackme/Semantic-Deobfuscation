"""
deobfuscator_engine.api_tokenizer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
API-aware tokenization and context-window chunking.
Enforces atomic preservation of security-critical Win32 APIs and .NET cmdlets,
preventing subword fragmentation (e.g., VirtualAllocEx -> Virt, ual, Alloc, Ex).
"""

import re
from typing import List, Dict, Any, Set, Tuple, Optional

CRITICAL_WIN32_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateThread", "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "QueueUserAPC", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
    "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
    "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetReadFile", "URLDownloadToFile",
    "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyEx",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
]

CRITICAL_DOTNET_CMDLETS = [
    "WebClient", "System.Net.WebClient", "DownloadFile", "DownloadString", "DownloadData", "UploadFile", "UploadData",
    "Invoke-Expression", "IEX", "Start-Process", "New-Object", "Add-Type",
    "FromBase64String", "ToBase64String", "Get-WmiObject", "Get-CimInstance",
    "Set-ItemProperty", "New-ItemProperty", "Invoke-Command", "Invoke-WebRequest",
    "Start-BitsTransfer", "Get-Process", "Stop-Process"
]

ALL_ATOMIC_SYMBOLS = sorted(CRITICAL_WIN32_APIS + CRITICAL_DOTNET_CMDLETS, key=len, reverse=True)

class APITokenizer:
    """Atomic symbol preservation tokenizer with sliding-window chunking."""

    def __init__(self, window_size: int = 4096, overlap_size: int = 512, overlap: Optional[int] = None):
        if overlap is not None:
            overlap_size = overlap
        self.window_size = window_size
        self.overlap_size = overlap_size
        self.step_size = max(1, window_size - overlap_size)
        self.atomic_symbols_set = {s.lower(): s for s in ALL_ATOMIC_SYMBOLS}
        # Build regex pattern for case-insensitive matching of atomic symbols
        escaped_symbols = [re.escape(s) for s in ALL_ATOMIC_SYMBOLS]
        self.atomic_regex = re.compile(r'\b(' + '|'.join(escaped_symbols) + r')\b', re.IGNORECASE)

    def tokenize(self, text: str) -> List[str]:
        """
        Tokenizes code while keeping critical Win32 APIs and cmdlets atomic.
        Standard code words are split normally; atomic APIs remain indivisible.
        """
        tokens = []
        last_pos = 0

        for match in self.atomic_regex.finditer(text):
            start, end = match.span()
            # Tokenize preceding text using simple identifier/operator tokenizer
            if start > last_pos:
                pre_text = text[last_pos:start]
                sub_tokens = self._basic_code_tokenize(pre_text)
                tokens.extend(sub_tokens)

            # Preserve matched API atomically
            matched_symbol = match.group(1)
            canonical = self.atomic_symbols_set.get(matched_symbol.lower(), matched_symbol)
            tokens.append(f"__API__{canonical}")
            last_pos = end

        if last_pos < len(text):
            trailing_text = text[last_pos:]
            tokens.extend(self._basic_code_tokenize(trailing_text))

        return tokens

    def _basic_code_tokenize(self, text: str) -> List[str]:
        # Split on non-alphanumeric except underscore and hyphen
        return [t for t in re.findall(r'[a-zA-Z0-9_\-]+|[^\s\w]', text) if t.strip()]

    def extract_atomic_apis(self, tokens: List[str]) -> List[str]:
        """Extracts list of preserved atomic APIs found in the token list."""
        apis = []
        for t in tokens:
            if t.startswith("__API__"):
                api_name = t.replace("__API__", "")
                if api_name not in apis:
                    apis.append(api_name)
        return apis

    def chunk_tokens(self, tokens: List[str]) -> List[Dict[str, Any]]:
        """
        Splits token sequence into overlapping sliding windows.
        Guarantees that state context is preserved across payload boundaries.
        """
        if not tokens:
            return []

        chunks = []
        total_tokens = len(tokens)
        chunk_idx = 0

        for start_idx in range(0, total_tokens, self.step_size):
            end_idx = min(start_idx + self.window_size, total_tokens)
            window_slice = tokens[start_idx:end_idx]
            contained_apis = self.extract_atomic_apis(window_slice)

            chunks.append({
                "chunk_index": chunk_idx,
                "start_token_idx": start_idx,
                "end_token_idx": end_idx,
                "token_count": len(window_slice),
                "tokens": window_slice,
                "contained_apis": contained_apis
            })
            chunk_idx += 1
            if end_idx >= total_tokens:
                break

        return chunks

    def process_text(self, text: str) -> Dict[str, Any]:
        """
        Full tokenization and chunking pipeline method.
        Returns total tokens, extracted atomic APIs, and chunk metadata.
        """
        full_tokens = self.tokenize(text)
        extracted_apis = self.extract_atomic_apis(full_tokens)
        chunks = self.chunk_tokens(full_tokens)

        return {
            "full_tokens": full_tokens,
            "total_tokens": len(full_tokens),
            "extracted_apis": extracted_apis,
            "chunks": chunks,
            "chunk_count": len(chunks),
            "window_size": self.window_size,
            "overlap": self.overlap_size
        }
