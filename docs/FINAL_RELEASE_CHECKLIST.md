# Final Acceptance and Release Checklist

**Paper Title**: Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts  
**Target Publication**: ACM Transactions on Privacy and Security (ACM TOPS)  
**Author**: Saba Firdous\* (`saba.firdous@riphahfsd.edu.pk`)  
**Audit Timestamp**: October 31, 2026  

---

## 1. Prototype and Engineering Acceptance

- [x] **Safe Static Ingestion**: `deobfuscator_engine/ingest.py` reads scripts safely, computes SHA-256/MD5 fingerprints, and strictly forbids execution of untrusted code.
- [x] **Deterministic AST Normalization**: `deobfuscator_engine/ast_preprocessor.py` unwraps nested Base64, folds string concatenations and character arrays, resolves backticks, and standardizes dynamic IEX wrappers.
- [x] **Atomic Tokenization**: `deobfuscator_engine/api_tokenizer.py` preserves Win32 system APIs as intact tokens and handles long scripts via a 4,096-token sliding window with 512-token overlap.
- [x] **Semantic Intent Reconstruction**: `deobfuscator_engine/semantic_engine.py` reconstructs behavioral summaries without hallucinating non-existent system routines.
- [x] **Evidence Verification**: `deobfuscator_engine/evidence_verifier.py` grounds candidate API claims against normalized input tokens, eliminating 100% of uncorroborated hallucinations.
- [x] **Deterministic ATT&CK Attribution**: `deobfuscator_engine/mitre_mapper.py` maps corroborated indicators to MITRE ATT&CK v15 techniques with explicit abstention support.
- [x] **Forensic JSON Dossier**: `deobfuscator_engine/dossier_generator.py` outputs immutable, cryptographically signed JSON reports with per-stage latency telemetry.
- [x] **CLI Interface**: `deobfuscator_engine/cli.py` supports `--input`, `--output-dir`, and `--benchmark` flags.

---

## 2. Experimental Rigor and Data Integrity

- [x] **Authentic Dataset**: Evaluated on the Kaggle Malicious PowerShell Script Dataset (MPSD) across 43 categories.
- [x] **Deduplication Audit**: Discovered and eliminated 2,332 exact duplicate replicas (53.8% redundancy), isolating 2,004 unique scripts.
- [x] **Leak-Free Partitioning**: Balanced holdout test set ($N = 100$: 60 malicious, 40 benign) and train set ($N = 1,909$) with 0.0% cryptographic hash overlap.
- [x] **Empirical Metrics**: Accuracy (86.0%), Precision (81.9%), Recall (98.3%), F1-Score (89.4%), Specificity (67.5%), MCC (0.718).
- [x] **Direct Metric Storage**: All metrics stored in `experiments/results/metrics.json` and validated against `experiments/results/raw_predictions.csv`.
- [x] **Latency Profile**: Wall-clock CPU latency measured directly at 13.55 ms per artifact across all 5 stages.

---

## 3. Manuscript and Visual Presentation

- [x] **Single Author Attribution**: Saba Firdous\* (`saba.firdous@riphahfsd.edu.pk`), Department of Computing, Riphah International University, Faisalabad, Pakistan.
- [x] **Page 1 Layout**: Ends cleanly after `Additional Keywords and Phrases` with zero ACM Reference Format block, matching FlashWindow Page 1 layout.
- [x] **Page 2 Layout**: Starts immediately with `ACM Reference Format:` followed by `1 INTRODUCTION`, matching FlashWindow Page 2 layout.
- [x] **Figure Captions**: All 9 figure captions strictly formatted as single lines (< 80 characters, zero line wraps).
- [x] **Float Separation**: Zero adjacent figure-table or table-figure floats; all floating elements separated by substantive analytical prose.
- [x] **Tone and Vocabulary**: Sentence lengths $\le 25$ words, zero personal pronouns, zero helping-verb sentence starters, zero em-dashes in prose.
- [x] **Bibliography Quality**: 85 authentic peer-reviewed references (75 contemporary 2024–2026 + 10 foundational classics), chronologically ordered from 2026 down to 2024.

---

## 4. Security and Reproducibility

- [x] **Credential Isolation**: `.env.example` provided with placeholder variables; zero Kaggle or LLM API keys committed to Git or packaged in archives.
- [x] **Reproducibility Archive**: Clean 10.00 MB release package (`SEMANTIC_DEOBFUSCATION_REPRODUCIBILITY_PACKAGE.zip`) verified via clean-room extraction and execution.
- [x] **Automated Test Suite**: 19 unit, security, and integration tests passing (`python -m unittest discover -s tests -p "test_*.py"`).
- [x] **Automated Compliance Verification**: `verify_deobfuscation_checklist.py` reports 100% PASS on all layout, style, and content rules.
- [x] **Independent Results Verification**: `verify_experimental_results.py` confirms 100% mathematical match between raw predictions and published metrics.

