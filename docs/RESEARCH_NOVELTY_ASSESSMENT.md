# FORMAL RESEARCH NOVELTY ASSESSMENT & LITERATURE POSITIONING
**Project**: Transformer-Based Semantic Deobfuscation  
**Target Venue**: ACM Transactions on Privacy and Security (ACM TOPS)  
**Authors**: Saba Firdous*, Shoaib Arshad (Riphah International University)  
**Date**: October 31, 2026  

---

## 1. Comparative Literature Matrix

| Dimension | Patsakis et al. (2024) [ACM TOPS / ArXiv] | Zhang et al. (2025) [Computers & Security] | Hu et al. (2026) [IEEE S&P / ArXiv] | **Our Proposed Framework (2026)** |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Empirical audit of commercial LLMs on malware scripts | PowerShell detection via AST Neural Networks (Power-ASTNN) | Systematic evaluation of LLMs on decompiled binary pseudocode | Autonomous multi-stage semantic deobfuscation and behavioral logic reconstruction |
| **Input Representation** | Raw script text snippets (JS, VBS, PS1) | PowerShell Abstract Syntax Tree (AST) statements | Decompiled C pseudocode (Ghidra / IDA Pro) | Normalized AST + Headless Decompiled IR with Atomic API tokens |
| **Tokenization Strategy** | Default model BPE / WordPiece | Word2Vec on AST subtrees | Standard subword tokenizers (cl100k, Llama BPE) | **Atomic Win32/.NET API Preservation Tokenizer** |
| **Model Architecture** | Black-box commercial LLMs (GPT-3.5/4) | Recursive AST Neural Network (Bi-GRU + Tree) | Zero-shot & fine-tuned open/closed LLMs | Open-weights Transformer (Llama-3.1-8B-Instruct) + Hybrid Verifier |
| **Deobfuscation vs Detection** | Deobfuscation (unverified textual translation) | Detection only (Binary classification 0/1) | Pseudocode simplification (variable renaming, dead code) | **Full Behavioral Reconstruction + MITRE ATT&CK Attribution** |
| **Hallucination Control** | None (Model outputs unverified text) | N/A (Pure classifier) | None (Empirical observation of hallucinations) | **Deterministic Evidence Verifier (Token Intersection Validation)** |
| **Standardized Reporting** | Raw text summaries | Numeric label only | Rewritten C code | **Standardized JSON Threat Intelligence Dossier** |
| **Evaluation Dataset** | 35 campaign samples (ad-hoc) | Mixed PowerShell corpus (12,000 scripts) | Synthetic C fixtures (O-LLVM, Tigress) | **Kaggle MPSD (4,336 scripts) + Multi-Obfuscation Benchmark** |

---

## 2. In-Depth Literature Analysis

### 2.1 Patsakis et al. (2024): Assessing LLMs in Malicious Code Deobfuscation
- **Key Insight**: Demonstrates that while LLMs possess intuitive semantic priors from code pre-training, prompting raw models on multi-layer obfuscation leads to severe hallucinations: the models invent standard library functions that do not exist in the payload, or miss evasive state-modifying payloads completely.
- **Limitation Addressed by Our System**: We demonstrate that raw prompting fails because the model lacks deterministic structural preprocessing. Our pipeline performs deterministic multi-layer decoding (Base64 streams, string concatenations, backtick stripping) *before* LLM ingestion, and introduces an Evidence Verification Layer that mathematically guarantees no invented API appears in the final forensic verdict.

### 2.2 Zhang et al. (2025): Power-ASTNN for PowerShell Detection
- **Key Insight**: Demonstrates that Abstract Syntax Trees capture syntactic hierarchy much more effectively than flat character or byte n-grams.
- **Limitation Addressed by Our System**: Power-ASTNN is purely a binary classifier; it outputs whether a script is malicious or benign, but gives zero explanation of *what* the script does, *how* it evades detection, or *which* ATT&CK tactics are being executed. Our system delivers behavioral reconstruction, generating human-readable intent summaries, extracted execution flow, and MITRE technique attribution.

### 2.3 Hu et al. (2026): Systematic Analysis of LLMs in Binary Decompilation
- **Key Insight**: Identifies the critical "tokenization boundary gap." Standard subword tokenizers (e.g., Byte-Pair Encoding) shatter specialized Win32 API names (e.g., `VirtualAllocEx` -> `Virt`, `ual`, `Alloc`, `Ex`) into disparate sub-tokens. Consequently, self-attention probability mass is dispersed across dead-code tokens rather than concentrating on security-critical APIs.
- **Limitation Addressed by Our System**: We introduce the **Atomic API Preservation Tokenizer**, which protects operational Win32 APIs and .NET cmdlets as indivisible semantic units. This directly forces transformer self-attention kernels to concentrate probability mass on state-modifying actions, validating the Attention Concentration hypothesis.

---

## 3. Revised Research Questions (RQs)

To ensure strict alignment with actual implemented capabilities and available ground truth:

- **RQ1 (Detection & Classification Accuracy)**: How accurately can the proposed hybrid pipeline discriminate between obfuscated malicious scripts and benign administrative software compared to static signatures, heuristic tools, and conventional machine learning baselines?
- **RQ2 (Semantic API Recovery Fidelity)**: How effectively does the Atomic API Preservation mechanism recover genuine operational system calls and cmdlets from heavily obfuscated scripts without suffering subword token fragmentation?
- **RQ3 (Hallucination Mitigation & Evidence Verification)**: To what extent does the Deterministic Evidence Verifier eliminate model-generated hallucinations and ungrounded API assertions compared to direct zero-shot LLM prompting?
- **RQ4 (MITRE ATT&CK Attribution Reliability)**: How accurately can the framework map extracted behavioral indicators to standardized MITRE ATT&CK Enterprise techniques?
- **RQ5 (Component Ablation Contributions)**: What is the isolated marginal contribution of each architectural stage (Base IR, AST Normalization, Atomic API Preservation, Attention Concentration, and Evidence Verification) to overall F1-score?
- **RQ6 (Operational Triage Velocity)**: What are the actual wall-clock execution latency and resource overheads across each pipeline stage, and how does throughput compare to manual reverse engineering?

