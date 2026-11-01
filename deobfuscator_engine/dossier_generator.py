"""
deobfuscator_engine.dossier_generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Production-Grade Forensic Dossier Generator.
Connects ingestion, AST normalization, atomic API tokenization, semantic reasoning,
evidence verification, and MITRE ATT&CK mapping into an immutable, audit-ready forensic report.
"""

import time
import json
import hmac
import hashlib
from typing import Dict, Any, Optional

from .ingest import Ingestor
from .ast_preprocessor import ASTPreprocessor
from .api_tokenizer import APITokenizer
from .semantic_engine import SemanticEngine
from .evidence_verifier import EvidenceVerifier
from .mitre_mapper import MitreMapper

class DossierGenerator:
    """Generates structured forensic dossiers for analyzed binaries and scripts."""

    def __init__(
        self,
        model_name: str = "Llama-3.1-8B-Instruct",
        window_size: int = 4096,
        overlap: int = 512,
        hallucination_threshold: float = 0.5,
        backend_type: str = "auto",
        backend: Optional[Any] = None
    ):
        self.ingestor = Ingestor()
        self.preprocessor = ASTPreprocessor()
        self.tokenizer = APITokenizer(window_size=window_size, overlap=overlap)
        self.semantic_engine = SemanticEngine(
            model_name=model_name,
            backend=backend,
            backend_type=backend_type
        )
        self.evidence_verifier = EvidenceVerifier(hallucination_threshold=hallucination_threshold)
        self.mitre_mapper = MitreMapper()

    def generate_from_file(self, file_path: str) -> Dict[str, Any]:
        """Runs the full 4-stage pipeline on a target file on disk."""
        total_start = time.perf_counter()

        # Stage 1: Ingestion and Decompilation / Script Ingestion
        t0 = time.perf_counter()
        ingest_meta = self.ingestor.ingest_file(file_path)
        code_payload = ingest_meta["content"]
        ingest_time = time.perf_counter() - t0

        return self._execute_pipeline(ingest_meta, code_payload, ingest_time, total_start)

    def generate_from_code(self, code_payload: str, filename: str = "sample.ps1") -> Dict[str, Any]:
        """Runs the full 4-stage pipeline on in-memory code."""
        total_start = time.perf_counter()

        t0 = time.perf_counter()
        ingest_meta = self.ingestor.ingest_bytes(code_payload.encode('utf-8', errors='ignore'), filename)
        ingest_time = time.perf_counter() - t0

        return self._execute_pipeline(ingest_meta, code_payload, ingest_time, total_start)

    def _execute_pipeline(
        self,
        ingest_meta: Dict[str, Any],
        raw_code: str,
        ingest_time: float,
        total_start: float
    ) -> Dict[str, Any]:
        """Internal execution coordinator for the 4-stage pipeline."""
        
        # Stage 1 (cont.): AST Preprocessing & Deobfuscation
        t_pre = time.perf_counter()
        preproc_result = self.preprocessor.preprocess(raw_code)
        normalized_code = preproc_result["normalized_code"]
        preproc_time = time.perf_counter() - t_pre

        # Stage 2: Tokenization & Atomic API Preservation
        t_tok = time.perf_counter()
        tok_result = self.tokenizer.process_text(normalized_code)
        token_time = time.perf_counter() - t_tok

        # Stage 3: Semantic Reconstruction & Attention Salience
        t_sem = time.perf_counter()
        sem_result = self.semantic_engine.analyze(
            normalized_code=normalized_code,
            token_chunks=tok_result["chunks"]
        )
        sem_time = time.perf_counter() - t_sem

        # Stage 4: Deterministic Evidence Verification & ATT&CK Mapping
        t_ver = time.perf_counter()
        verification_result = self.evidence_verifier.verify_findings(
            candidate_apis=sem_result["candidate_apis"],
            ground_truth_extracted_apis=tok_result["extracted_apis"],
            full_tokens=tok_result["full_tokens"]
        )

        # Corroborated API names for ATT&CK mapping
        verified_api_names = [a if isinstance(a, str) else a["api_name"] for a in verification_result["corroborated_apis"]]
        mitre_result = self.mitre_mapper.map_techniques(
            verified_apis=verified_api_names,
            normalized_code=normalized_code
        )
        ver_time = time.perf_counter() - t_ver

        total_elapsed = time.perf_counter() - total_start

        # Determine finalized forensic verdict with evidence verification grounding
        raw_verdict = sem_result["predicted_verdict"]
        has_corroborated_apis = len(verification_result["corroborated_apis"]) > 0
        has_mitre_ttps = len(mitre_result["primary_techniques"]) > 0

        if raw_verdict == "MALICIOUS":
            # Malicious verdict requires grounded corroboration
            if has_corroborated_apis or has_mitre_ttps:
                final_verdict = "MALICIOUS"
            else:
                # Refuted by verifier: uncorroborated candidate APIs were hallucinations
                final_verdict = "BENIGN"
        else:
            # If semantic engine predicted BENIGN, but high-severity malicious APIs or MITRE TTPs were verified
            if has_mitre_ttps and any(t in ["T1055", "T1071", "T1059", "T1027", "T1106", "T1486"] for t in mitre_result["primary_techniques"]):
                final_verdict = "MALICIOUS"
            elif has_corroborated_apis and any(a in ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "DownloadFile", "DownloadString", "WebClient"] for a in verified_api_names):
                final_verdict = "MALICIOUS"
            else:
                final_verdict = "BENIGN"

        dossier = {
            "dossier_version": "2.0-ACM-TOPS",
            "artifact_metadata": {
                "sha256": ingest_meta["sha256"],
                "md5": ingest_meta["md5"],
                "file_size_bytes": ingest_meta["file_size_bytes"],
                "file_type": ingest_meta["file_type"],
                "safe_mode": ingest_meta["safe_mode"]
            },
            "preprocessing_metrics": {
                "layers_unwrapped": preproc_result["layers_unwrapped"],
                "structural_indicators": preproc_result["structural_indicators"],
                "decoding_steps": preproc_result["decoding_steps"]
            },
            "tokenization_metrics": {
                "total_tokens": tok_result["total_tokens"],
                "chunk_count": tok_result["chunk_count"],
                "window_size": tok_result["window_size"],
                "overlap": tok_result["overlap"],
                "raw_extracted_apis_count": len(tok_result["extracted_apis"])
            },
            "forensic_assessment": {
                "verdict": final_verdict,
                "confidence_score": verification_result["confidence_score"],
                "backend_type": sem_result.get("model_metadata", {}).get("backend_type", "Deterministic_Offline_Transformer_Aligned"),
                "model_name": self.semantic_engine.model_name,
                "intent_summary": sem_result["intent_summary"],
                "execution_flow": sem_result["execution_flow"],
                "target_artifacts": sem_result["target_artifacts"],
                "corroborated_apis": verification_result["corroborated_apis"],
                "rejected_hallucinations": verification_result["rejected_hallucinations"],
                "hallucination_detected": verification_result["hallucination_detected"],
                "attention_salience": sem_result["attention_salience"]
            },
            "mitre_attack_attribution": {
                "primary_techniques": mitre_result["primary_techniques"],
                "technique_count": mitre_result["technique_count"],
                "mapped_ttps": mitre_result["mapped_ttps"]
            },
            "pipeline_latencies": {
                "stage1_ingest_sec": round(ingest_time, 4),
                "stage1_preprocess_sec": round(preproc_time, 4),
                "stage2_tokenize_sec": round(token_time, 4),
                "stage3_semantic_sec": round(sem_time, 4),
                "stage4_verify_mitre_sec": round(ver_time, 4),
                "total_wall_clock_sec": round(total_elapsed, 4)
            }
        }

        # Compute HMAC-SHA256 integrity seal for forensic provenance and tamper evidence
        canonical_bytes = json.dumps(dossier, sort_keys=True).encode("utf-8")
        secret_key = b"ACM_TOPS_SEMANTIC_DEOBFUSCATION_PROVENANCE_KEY_2026"
        dossier["integrity_seal"] = {
            "algorithm": "HMAC-SHA256",
            "digest": hmac.new(secret_key, canonical_bytes, hashlib.sha256).hexdigest(),
            "content_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
            "tamper_evident": True
        }

        return dossier

    @staticmethod
    def verify_integrity_seal(
        dossier: Dict[str, Any],
        secret_key: bytes = b"ACM_TOPS_SEMANTIC_DEOBFUSCATION_PROVENANCE_KEY_2026"
    ) -> bool:
        """Verifies the HMAC-SHA256 integrity seal of a generated dossier."""
        if "integrity_seal" not in dossier:
            return False
        stored_seal = dossier["integrity_seal"].get("digest")
        if not stored_seal:
            return False
        dossier_copy = {k: v for k, v in dossier.items() if k != "integrity_seal"}
        canonical_bytes = json.dumps(dossier_copy, sort_keys=True).encode("utf-8")
        expected_seal = hmac.new(secret_key, canonical_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(stored_seal, expected_seal)

    def save_dossier_json(self, dossier: Dict[str, Any], output_path: str) -> None:
        """Saves formatted forensic dossier to disk."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(dossier, f, indent=2)
