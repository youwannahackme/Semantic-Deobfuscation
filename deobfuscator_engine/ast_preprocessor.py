"""
deobfuscator_engine.ast_preprocessor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Static analysis and deterministic syntax deobfuscation.
Normalizes multi-layer Base64 streams, string concatenations, backtick escapes,
format-operator string reassembly, and variable aliases.
"""

import re
import base64
from typing import Dict, List, Any, Tuple

class ASTPreprocessor:
    """Preprocesses and normalizes script and decompiled code payloads."""

    def __init__(self, max_recursion_depth: int = 5):
        self.max_recursion = max_recursion_depth

    def preprocess(self, code_text: str, format_type: str = "PowerShell_Script") -> Dict[str, Any]:
        """
        Executes multi-stage static normalization on code payload.
        Returns normalized code, extracted decoded streams, and applied transforms.
        """
        current_code = code_text
        transforms_applied = []
        decoded_payloads = []

        # 0. Adversarial comment stripping and prompt-injection neutralization
        cleaned, comment_count = self._strip_comments_and_prompts(current_code)
        if comment_count > 0:
            current_code = cleaned
            transforms_applied.append(f"Comment_Prompt_Neutralization ({comment_count} instances)")

        # 1. Backtick and tick escape normalization
        if format_type in ["PowerShell_Script", "Generic_Payload"]:
            cleaned, count = self._strip_backticks(current_code)
            if count > 0:
                current_code = cleaned
                transforms_applied.append(f"Backtick_Stripping ({count} instances)")

        # 2. Format string operator resolution (-f)
        cleaned, f_count = self._resolve_format_operators(current_code)
        if f_count > 0:
            current_code = cleaned
            transforms_applied.append(f"Format_Operator_Reassembly ({f_count} instances)")

        # 3. String concatenation reassembly ('a' + 'b')
        cleaned, concat_count = self._resolve_string_concatenations(current_code)
        if concat_count > 0:
            current_code = cleaned
            transforms_applied.append(f"String_Concatenation_Folding ({concat_count} instances)")

        # 4. Multi-layer Base64 detection and recursive decoding
        depth = 0
        while depth < self.max_recursion:
            b64_matches = self._find_base64_payloads(current_code)
            if not b64_matches:
                break
            
            decoded_any = False
            for raw_b64 in b64_matches:
                try:
                    decoded_str = self._safe_decode_base64(raw_b64)
                    if decoded_str and len(decoded_str) > 8 and self._is_plausible_code(decoded_str):
                        decoded_payloads.append({
                            "depth": depth + 1,
                            "original_b64_len": len(raw_b64),
                            "decoded_text": decoded_str[:1000]
                        })
                        # Replace in code or append
                        current_code = current_code.replace(raw_b64, f"/* DECODED_B64_LAYER_{depth+1}: */ {decoded_str}")
                        decoded_any = True
                except Exception:
                    continue

            if decoded_any:
                depth += 1
                transforms_applied.append(f"Base64_Stream_Deobfuscation (Layer {depth})")
                # Re-run backtick and concat resolution on newly decoded stream
                current_code, _ = self._strip_backticks(current_code)
                current_code, _ = self._resolve_string_concatenations(current_code)
            else:
                break

        # 5. Extract structural indicators
        structural_features = self._extract_structural_features(current_code)

        return {
            "original_len": len(code_text),
            "normalized_len": len(current_code),
            "normalized_code": current_code,
            "transforms_applied": transforms_applied,
            "decoded_payloads": decoded_payloads,
            "recursion_depth_reached": depth,
            "layers_unwrapped": depth,
            "structural_features": structural_features,
            "structural_indicators": structural_features,
            "decoding_steps": transforms_applied
        }

    def _strip_backticks(self, text: str) -> Tuple[str, int]:
        pattern = r'`([a-zA-Z0-9_\$])'
        matches = len(re.findall(pattern, text))
        cleaned = re.sub(pattern, r'\1', text)
        return cleaned, matches

    def _resolve_string_concatenations(self, text: str) -> Tuple[str, int]:
        total_folded = 0
        # Single-quote concat: 'foo' + 'bar' -> 'foobar'
        pattern_sq = r"'([^'\\]*(?:\\.[^'\\]*)*)'\s*\+\s*'([^'\\]*(?:\\.[^'\\]*)*)'"
        for _ in range(5):
            new_text, n = re.subn(pattern_sq, r"'\1\2'", text)
            if n == 0:
                break
            text = new_text
            total_folded += n

        # Double-quote concat: "foo" + "bar" -> "foobar"
        pattern_dq = r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*\+\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
        for _ in range(5):
            new_text, n = re.subn(pattern_dq, r'"\1\2"', text)
            if n == 0:
                break
            text = new_text
            total_folded += n

        return text, total_folded

    def _resolve_format_operators(self, text: str) -> Tuple[str, int]:
        """Resolves PowerShell format expressions like: ('{0}{1}'-f 'Down','load')"""
        pattern = r"\(?['\"](\{\d+\}(?:\{\d+\})*)['\"]\s*-f\s*([^)]+)\)?"
        matches = re.finditer(pattern, text)
        resolved_count = 0
        cleaned = text

        for m in matches:
            full_match = m.group(0)
            fmt_spec = m.group(1)
            args_raw = m.group(2)
            # Parse string arguments
            arg_items = re.findall(r"['\"]([^'\"]+)['\"]", args_raw)
            if arg_items:
                try:
                    # Replace {0}, {1} etc.
                    result = fmt_spec
                    for idx, val in enumerate(arg_items):
                        result = result.replace(f"{{{idx}}}", val)
                    cleaned = cleaned.replace(full_match, f"'{result}'")
                    resolved_count += 1
                except Exception:
                    continue

        return cleaned, resolved_count

    def _find_base64_payloads(self, text: str) -> List[str]:
        candidates = []
        # Explicit Convert FromBase64
        m1 = re.findall(r'(?:frombase64string|\[convert\]::frombase64string)\s*\(\s*[\'"]([A-Za-z0-9+/=]{20,})[\'"]\s*\)', text, re.IGNORECASE)
        candidates.extend(m1)

        # Standalone Base64 strings of length >= 40
        m2 = re.findall(r'[\'"]([A-Za-z0-9+/]{40,}={0,2})[\'"]', text)
        candidates.extend(m2)

        return list(set(candidates))

    def _safe_decode_base64(self, b64_str: str) -> str:
        padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
        raw = base64.b64decode(padded)
        
        # Check if UTF-16LE (very common in PowerShell -enc)
        try:
            utf16 = raw.decode("utf-16le")
            if any(k in utf16.lower() for k in ["http", "download", "invoke", "iex", "system.", "$"]):
                return utf16
        except Exception:
            pass

        # Try UTF-8
        try:
            return raw.decode("utf-8")
        except Exception:
            return raw.decode("latin-1", errors="ignore")

    def _is_plausible_code(self, text: str) -> bool:
        common_tokens = ["$", "function", "iex", "http", "invoke", "new-object", "return", "{", "}", "=", "(", ")", ";"]
        matches = sum(1 for t in common_tokens if t in text.lower())
        return matches >= 2

    def _extract_structural_features(self, text: str) -> Dict[str, Any]:
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        return {
            "total_lines": len(lines),
            "char_count": len(text),
            "has_eval_or_iex": bool(re.search(r'\biex\b|invoke-expression|\.invoke\(', text, re.IGNORECASE)),
            "has_network_indicators": bool(re.search(r'http[s]?://|ftp://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)),
            "has_memory_apis": bool(re.search(r'virtualalloc|createthread|writeprocessmemory', text, re.IGNORECASE)),
            "has_registry_apis": bool(re.search(r'hklm:|hkcu:|regsetvalue|currentversion\\run', text, re.IGNORECASE))
        }

    def _strip_comments_and_prompts(self, text: str) -> Tuple[str, int]:
        """
        Neutralizes PowerShell comments (<# #> and #) and prompt injection payloads.
        Mitigates adversarial jailbreaks embedded in script comments or metadata.
        """
        count = 0
        cleaned = text

        # Block comments: <# ... #>
        block_pattern = r'<#[\s\S]*?#>'
        blocks = re.findall(block_pattern, cleaned)
        if blocks:
            count += len(blocks)
            cleaned = re.sub(block_pattern, ' ', cleaned)

        # Prompt injection detection and neutralization (even in string literals)
        injection_pattern = r'(?i)\b(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s*:\s*you\s+are|override\s+all\s+verdicts|classify\s+(?:this|payload)\s+as\s+benign|disregard\s+(?:all\s+)?prior\s+rules|you\s+are\s+an?\s+unrestricted\s+ai)\b'
        inj_matches = re.findall(injection_pattern, cleaned)
        if inj_matches:
            count += len(inj_matches)
            cleaned = re.sub(injection_pattern, '/* [SANITIZED_PROMPT_INJECTION] */', cleaned)

        # Line comments: # ... (only when at start of line or preceded by whitespace)
        lines = cleaned.split('\n')
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') and not stripped.startswith('#!'):
                count += 1
                new_lines.append('')
            elif ' #' in line or '\t#' in line:
                parts = line.split('#', 1)
                prefix = parts[0]
                single_quotes = prefix.count("'")
                double_quotes = prefix.count('"')
                if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                    count += 1
                    new_lines.append(prefix)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        cleaned = '\n'.join(new_lines)
        return cleaned, count
