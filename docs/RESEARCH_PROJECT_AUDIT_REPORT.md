# COMPREHENSIVE RESEARCH PROJECT AUDIT REPORT
**Project Title**: Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts  
**Target Venue**: ACM Transactions on Privacy and Security (ACM TOPS)  
**Authors**: Saba Firdous* (Corresponding Author), Shoaib Arshad (Department of Computing, Riphah International University, Faisalabad, Pakistan)  
**Audit Date**: October 31, 2026  

---

## 1. Executive Summary & Audit Scope

This audit evaluates the scientific defensibility, experimental reproducibility, implementation completeness, dataset provenance, and manuscript integrity of the existing research project. The objective is to identify all theoretical, empirical, and architectural gaps, establish an authentic experimental foundation using real Kaggle datasets, build a functional modular prototype, execute real experiments, and rewrite the manuscript in accordance with verified empirical evidence.

---

## 2. Research Problem, Objectives & Claimed Contributions

### 2.1 Research Problem
Adversarial malware authors increasingly employ sophisticated semantics-preserving code obfuscation (including multi-layer Base64 encoding, dynamic string assembly, instruction substitution, control-flow flattening, and dynamic API hashing) to evade static signature detection and traditional machine learning classifiers. Conventional static disassembly and heuristic scanners fail because syntactic transformations destroy local n-gram patterns and signature anchors, while manual reverse engineering requires 45–120 minutes per sample.

### 2.2 Claimed Research Contributions
The manuscript asserts four primary technical contributions:
1. **Four-Stage Autonomous Deobfuscation Pipeline**: Integrating headless decompilation/AST parsing, atomic API token preservation, zero-shot transformer reasoning (Llama-3.1-8B), and structured JSON dossier generation.
2. **Atomic Win32 API Preservation**: An API-aware tokenization mechanism that protects operational system calls (e.g., `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`) from subword fragmentation during tokenization.
3. **Rigorous Quantitative Evaluation**: A reported 92.9% accuracy, 95.9% precision, 94.0% recall, and 94.9% F1-score across 70 evaluated binary/script samples, outperforming VirusTotal signatures (64.1% F1) and Random Forest ML (86.2% F1).
4. **Operational Latency Acceleration**: An 18-fold reduction in triage turnaround latency from 45–120 minutes down to 3–5 minutes per sample.

---

## 3. Critical Gap Analysis & Verification Audit

| Research Component | Current Status | Scientific & Implementation Gap | Required Remediation |
| :--- | :--- | :--- | :--- |
| **Datasets & Provenance** | Partially Supported | Historical manuscript referenced 70 samples (30 synthetic, 20 wild, 20 benign), but lacked full raw sample archives, per-sample predictions, and leak-free split artifacts on disk. | Ingest authentic Kaggle MPSD dataset (4,336 real-world PowerShell scripts across 45 categories) and dynamic API sequences. Establish clean stratified splits with SHA-256 manifests. |
| **Prototype Implementation** | Incomplete / Dispersed | Ingestion, parsing, and figure-generation scripts existed as disjoint Python scripts without a unified, modular Python engine (`deobfuscator_engine/`). | Build a production-grade, modular Python package: secure ingestion, AST preprocessing, API tokenization, semantic analysis, deterministic evidence verification, ATT&CK mapping, and CLI. |
| **Experimental Baselines** | Synthetic Summary | Baselines (Hash lookup, VirusTotal, Random Forest, Base LLM) were recorded in summary tables without persistent raw prediction matrices or reproducible training scripts. | Train real scikit-learn models (TF-IDF + Logistic Regression, Random Forest on AST/n-gram features), run real signature scanners, execute prototype inference, and persist raw confusion matrices. |
| **Theoretical Claims (Proposition 1)** | Needs Scrutiny | "Attention Dominance" proposition was stated with a proof sketch, but attention weights must be empirically verified against extracted token salience rather than assumed causal proof. | Refine proposition to an empirical attention-concentration hypothesis and validate attention mass over operational APIs vs syntactic dead code using actual model token representations. |
| **Figures & Tables** | Manually Generated | Figures and tables were generated from hardcoded constants rather than directly reading raw CSV/JSON evaluation outputs. | Re-implement figure and table generation pipelines to dynamically load verified experiment logs, generating publication-grade SVGs/PNGs and Word booktabs tables. |
| **Bibliographic Audit** | Formally Structured | 85 citations exist in descending 2026–2024 order, but key contemporary papers (Patsakis et al. 2024, Zhang et al. 2025 Power-ASTNN, Hu et al. 2026) must be rigorously evaluated for research novelty positioning. | Conduct formal literature review on LLM deobfuscation, identify exact research gap, and integrate citations with accurate publisher DOIs. |

---

## 4. Distinction Between Classification, Deobfuscation, and Attribution

To maintain strict scientific honesty and avoid methodological conflation:
1. **Malware Classification** determines binary or multi-class maliciousness (Malicious vs Benign) based on statistical feature distributions. High classification accuracy does **not** prove semantic code recovery.
2. **Semantic Deobfuscation** normalizes obfuscated syntax back to an interpretable canonical representation (e.g., resolving Base64 layers, unrolling XOR loops, eliminating dead code).
3. **Behavioral Reconstruction** synthesizes the execution logic, data dependencies, and state modifications intended by the code.
4. **MITRE ATT&CK Attribution** associates extracted behavioral indicators with standardized adversary tactic and technique identifiers.

The redesigned methodology will explicitly evaluate these dimensions with distinct, task-appropriate metrics.

---

## 5. Improvement Roadmap

- **Phase 1**: Literature Review & Research Novelty positioning against Patsakis et al. (2024), Zhang et al. (2025), and Hu et al. (2026).
- **Phase 2**: Dataset ingestion, deduplication, stratification, and SHA-256 manifest generation using Kaggle MPSD.
- **Phase 3**: Modular research prototype construction (`deobfuscator_engine/`).
- **Phase 4**: Execution of real experiments, baseline comparisons, and ablation studies with persistent raw outputs.
- **Phase 5**: Automated figure and table regeneration directly from raw experimental data.
- **Phase 6**: Manuscript reconstruction in full ACM TOPS compliance, formal reference verification, and final packaging.

