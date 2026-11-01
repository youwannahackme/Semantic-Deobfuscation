"""
deobfuscator_engine.mitre_mapper
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic MITRE ATT&CK v15 Enterprise Knowledge Base and Attribution Mapper.
Maps verified Win32 APIs, .NET cmdlets, and structural behavior patterns
to standardized ATT&CK tactics, techniques, and procedures.
"""

from typing import List, Dict, Any, Set, Optional

MITRE_ATTACK_KNOWLEDGE_BASE = [
    {
        "technique_id": "T1055.001",
        "technique_name": "Process Injection: Dynamic-link Library Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "trigger_apis": {"createremotethread", "virtualallocex", "writeprocessmemory"},
        "min_match": 2,
        "description": "Injects dynamic library into remote process address space."
    },
    {
        "technique_id": "T1055.002",
        "technique_name": "Process Injection: Portable Executable Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "trigger_apis": {"virtualalloc", "createthread", "memset", "writeprocessmemory"},
        "min_match": 2,
        "description": "Allocates RWX memory and copies shellcode payload for thread execution."
    },
    {
        "technique_id": "T1055.004",
        "technique_name": "Process Injection: Asynchronous Procedure Call",
        "tactic": "Defense Evasion, Privilege Escalation",
        "trigger_apis": {"queueuserapc"},
        "min_match": 1,
        "description": "Queues malicious APC routine targeting thread execution queue."
    },
    {
        "technique_id": "T1055.012",
        "technique_name": "Process Injection: Process Hollowing",
        "tactic": "Defense Evasion, Privilege Escalation",
        "trigger_apis": {"ntunmapviewofsection", "zwunmapviewofsection"},
        "min_match": 1,
        "description": "Unmaps legitimate process image and hollows memory with adversary payload."
    },
    {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "trigger_apis": {"downloadfile", "downloadstring", "httpsendrequestw", "internetopenurlw", "invoke-webrequest", "webclient", "system.net.webclient"},
        "min_match": 1,
        "description": "Communicates via HTTP/HTTPS protocols to retrieve external payloads or beacon."
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "trigger_apis": {"invoke-expression", "iex", "start-process"},
        "min_match": 1,
        "description": "Executes dynamic PowerShell expressions and commands in system memory."
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "trigger_apis": {"frombase64string", "tobase64string"},
        "min_match": 1,
        "description": "Conceals executable code and strings inside encoded byte streams."
    },
    {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "Execution",
        "trigger_apis": {"add-type", "loadlibrary", "getprocaddress", "virtualalloc", "virtualallocex", "createremotethread", "writeprocessmemory"},
        "min_match": 1,
        "description": "Interacts directly with underlying Windows native API calls via dynamic compilation."
    },
    {
        "technique_id": "T1547.001",
        "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence, Privilege Escalation",
        "trigger_apis": {"regsetvalueexw", "set-itemproperty", "regcreatekeyex"},
        "min_match": 1,
        "description": "Establishes persistence by modifying Windows autorun registry keys."
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "trigger_apis": {"cryptencrypt", "cryptcreatehash"},
        "min_match": 1,
        "description": "Encrypts target documents with symmetric/asymmetric cryptographic keys."
    }
]

class MITREMapper:
    """Attributes corroborated behaviors to MITRE ATT&CK Enterprise techniques."""

    def __init__(self):
        self.kb = MITRE_ATTACK_KNOWLEDGE_BASE

    def attribute(self, verified_apis: List[str], structural_features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Maps list of verified APIs and structural indicators to MITRE ATT&CK.
        Supports abstention when insufficient evidence exists.
        """
        api_set = set(a.lower() for a in verified_apis)
        matched_techniques = []

        for entry in self.kb:
            overlap = api_set.intersection(entry["trigger_apis"])
            if len(overlap) >= entry["min_match"]:
                matched_techniques.append({
                    "technique_id": entry["technique_id"],
                    "technique_name": entry["technique_name"],
                    "tactic": entry["tactic"],
                    "matched_apis": sorted(list(overlap)),
                    "description": entry["description"],
                    "attribution_confidence": round(min(1.0, len(overlap) / float(entry["min_match"]) * 0.9), 2)
                })

        # Check structural flags if passed
        if structural_features:
            if structural_features.get("has_eval_or_iex") and not any(t["technique_id"] == "T1059.001" for t in matched_techniques):
                matched_techniques.append({
                    "technique_id": "T1059.001",
                    "technique_name": "Command and Scripting Interpreter: PowerShell",
                    "tactic": "Execution",
                    "matched_apis": ["IEX_Dynamic_Evaluation"],
                    "description": "Detected dynamic execution via script interpreter.",
                    "attribution_confidence": 0.85
                })

        # Abstention handling
        has_sufficient_evidence = len(matched_techniques) > 0

        return {
            "has_sufficient_evidence": has_sufficient_evidence,
            "matched_techniques_count": len(matched_techniques),
            "attributions": matched_techniques,
            "primary_tactic": matched_techniques[0]["tactic"] if matched_techniques else "Insufficient_Evidence",
            "primary_technique": matched_techniques[0]["technique_id"] if matched_techniques else "None"
        }

    def map_techniques(self, verified_apis: List[str], normalized_code: str = "") -> Dict[str, Any]:
        """Convenience method conforming to paper architecture."""
        structural = {
            "has_eval_or_iex": any(k in normalized_code.lower() for k in ["iex", "invoke-expression"])
        }
        res = self.attribute(verified_apis, structural)
        primary_techniques = [t["technique_id"].split(".")[0] for t in res["attributions"]]
        return {
            "primary_techniques": list(dict.fromkeys(primary_techniques)),
            "technique_count": res["matched_techniques_count"],
            "mapped_ttps": res["attributions"]
        }

# Alias for casing flexibility
MitreMapper = MITREMapper
