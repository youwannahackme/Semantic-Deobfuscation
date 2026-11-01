# Limitations and Threats to Scientific Validity

**Manuscript Title**: Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts  
**Target Venue**: ACM Transactions on Privacy and Security (ACM TOPS)  
**Document Classification**: Transparent Methodological Audit  

---

## 1. Threats to Internal Validity

### 1.1 Simulated Attention Salience vs. Raw Weight Introspection
- **Threat**: The prototype implements attention salience weighting over atomic Win32 tokens rather than directly extracting hidden-layer attention matrices from high-parameter foundation models.
- **Mitigation & Boundary**: The manuscript explicitly distinguishes between mathematical multi-head attention weights and token salience approximations. The core empirical findings do not depend on internal layer introspection; rather, they demonstrate that prioritizing atomic API tokens in the prompt context anchors model generation to verified malicious indicators.

### 1.2 Heuristic vs. Full Dynamic Emulation
- **Threat**: Static AST normalization handles syntactic transformations (nested Base64, string concatenation, format operators, backticks) but cannot unpack self-modifying payloads that execute runtime decryptor loops dependent on environmental key derivation.
- **Mitigation & Boundary**: The manuscript frames the proposed system as a static, pre-execution triage filter. Highly evasive, environmentally keyed binaries still require isolated sandbox execution or full symbolic execution.

---

## 2. Threats to External Validity

### 2.1 Language and Ecosystem Specificity
- **Threat**: Empirical validation was conducted on the Kaggle Malicious PowerShell Script Dataset (MPSD). While PowerShell represents a primary adversary vector in enterprise living-off-the-land attacks, the findings may not directly generalize to native compiled x86/x64 binaries, Go binaries, or Linux shell scripts without retraining or adapting AST grammars.
- **Mitigation & Boundary**: The ingestion and headless Ghidra decompilation module is architected to produce C pseudocode for PE binaries, demonstrating architectural generalizability; however, empirical claims are strictly bounded to the MPSD benchmark.

### 2.2 Test Set Size and Class Balance ($N = 100$)
- **Threat**: Although derived from a deduplicated corpus of 2,004 scripts, the primary benchmark consists of 100 balanced holdout samples (60 malicious, 40 benign).
- **Mitigation & Boundary**: The 100 test samples were selected using stratified sampling across four distinct obfuscation classes. Confidence intervals and exact per-sample predictions are published openly in `experiments/results/raw_predictions.csv` to ensure reproducibility.

---

## 3. Threats to Construct Validity

### 3.1 Binary Verdict Formulation vs. Granular Threat Actor Attribution
- **Threat**: The evaluation reduces semantic deobfuscation to binary detection metrics (Accuracy, Precision, Recall, F1) to compare against supervised baselines, which might obscure the qualitative richness of behavioral logic recovery.
- **Mitigation & Boundary**: In addition to classification metrics, the research records structured JSON dossiers containing extracted execution intents, verified API arguments, and MITRE ATT&CK technique IDs (T1055, T1071, T1059, T1027, T1106, T1486).

### 3.2 False Positive Rate on Benign Administrative Scripts
- **Threat**: A specificity of 67.5% (13 false positives out of 40 benign samples) indicates that complex administrative scripts employing WMI reflection are flagged by heuristic triggers.
- **Mitigation & Boundary**: The Evidence Verifier incorporates confidence scoring and supports abstention, allowing enterprise SOC deployments to route ambiguous administrative scripts to secondary analyst review rather than generating hard block actions.

---

## 4. Ethical Considerations and Dual-Use Mitigation

- **Dual-Use Risk**: Techniques used to normalize and deobfuscate scripts could theoretically be inverted by malware authors to test obfuscation resilience against LLM-based endpoint filters.
- **Ethical Mitigation**: The prototype is published under research and educational terms with zero active exploitation capabilities. The system operates strictly as a defensive analysis tool and does not execute untrusted binaries or scripts during ingestion.

