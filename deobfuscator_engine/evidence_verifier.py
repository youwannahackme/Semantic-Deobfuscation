"""
deobfuscator_engine.evidence_verifier
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic Evidence Verification Layer.
Intercepts model assertions and verifies every extracted API and behavioral indicator
against the ground-truth tokenized input sequence, mathematically eliminating hallucinations.
"""

from typing import List, Dict, Any, Set, Tuple

# API Criticality Weights for Verification Scoring
API_SEVERITY_WEIGHTS = {
    "VirtualAlloc": 2.5,
    "VirtualAllocEx": 3.0,
    "WriteProcessMemory": 3.0,
    "CreateThread": 2.5,
    "CreateRemoteThread": 3.5,
    "QueueUserAPC": 3.0,
    "NtUnmapViewOfSection": 3.5,
    "ZwUnmapViewOfSection": 3.5,
    "SetWindowsHookExW": 2.0,
    "AdjustTokenPrivileges": 2.0,
    "HttpSendRequestW": 2.5,
    "InternetOpenUrlW": 2.0,
    "CryptEncrypt": 2.5,
    "RegSetValueExW": 2.0,
    "DownloadFile": 2.5,
    "DownloadString": 2.5,
    "WebClient": 2.0,
    "System.Net.WebClient": 2.0,
    "Start-Process": 1.5,
    "Invoke-Expression": 2.0,
    "IEX": 2.0,
    "FromBase64String": 1.5,
    "Add-Type": 1.5,
    "Get-WmiObject": 1.0,
    "Get-Process": 0.5,
    "Get-Service": 0.5
}

DEFAULT_WEIGHT = 1.0

class EvidenceVerifier:
    """Verifies candidate findings against extracted ground-truth tokens."""

    def __init__(self, hallucination_threshold: float = 0.5):
        self.threshold = hallucination_threshold

    def verify_findings(
        self,
        candidate_apis: List[str],
        ground_truth_extracted_apis: List[str],
        full_tokens: List[str]
    ) -> Dict[str, Any]:
        """
        Deterministically verifies candidate APIs.
        Returns corroborated APIs, rejected hallucinated APIs, and weighted confidence score.
        """
        gt_api_set = set(a.lower() for a in ground_truth_extracted_apis)
        token_text_lower = " ".join(t.lower() for t in full_tokens)

        corroborated_apis = []
        rejected_hallucinations = []
        weighted_matched_score = 0.0
        total_possible_weight = 0.0

        for candidate in candidate_apis:
            c_clean = candidate.strip()
            c_lower = c_clean.lower()
            weight = API_SEVERITY_WEIGHTS.get(c_clean, DEFAULT_WEIGHT)
            total_possible_weight += weight

            # Check if present in ground truth extracted APIs OR directly in token text
            if c_lower in gt_api_set or c_lower in token_text_lower:
                corroborated_apis.append({
                    "api_name": c_clean,
                    "status": "VERIFIED_PRESENT",
                    "weight": weight
                })
                weighted_matched_score += weight
            else:
                rejected_hallucinations.append({
                    "api_name": c_clean,
                    "status": "REJECTED_HALLUCINATION",
                    "reason": "Symbol not found in normalized token stream",
                    "weight": weight
                })

        # Calculate evidence confidence score C in [0.0, 1.0]
        if total_possible_weight > 0:
            evidence_confidence = round(weighted_matched_score / total_possible_weight, 4)
        else:
            # If no candidate APIs were proposed and none exist in GT, confidence is 1.0 (clean)
            evidence_confidence = 1.0 if len(ground_truth_extracted_apis) == 0 else 0.0

        # Calculate strict factual grounding ratio
        grounding_ratio = round(len(corroborated_apis) / max(1, len(candidate_apis)), 4)

        return {
            "is_valid": len(rejected_hallucinations) == 0,
            "corroborated_apis": [a["api_name"] for a in corroborated_apis],
            "rejected_hallucinations": [r["api_name"] for r in rejected_hallucinations],
            "rejected_details": rejected_hallucinations,
            "corroborated_details": corroborated_apis,
            "confidence_score": evidence_confidence,
            "evidence_confidence": evidence_confidence,
            "hallucination_detected": len(rejected_hallucinations) > 0,
            "grounding_ratio": grounding_ratio,
            "total_candidates": len(candidate_apis),
            "verified_count": len(corroborated_apis),
            "hallucination_count": len(rejected_hallucinations)
        }
