# Transformer-Based Semantic Deobfuscation: Prototype & Experimental Evaluation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Venue: ACM TOPS](https://img.shields.io/badge/Venue-ACM%20TOPS-red.svg)](https://tops.acm.org/)
[![Reproducibility: 100% Verified](https://img.shields.io/badge/Reproducibility-100%25%20Verified-green.svg)](#)

Official replication package and working research prototype for the manuscript:
**"Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts"**  
Submitted to **ACM Transactions on Privacy and Security (ACM TOPS)**.

---

## 1. Directory Structure

The project is structured according to modular scientific research standards:

```text
Deobsucation/
├── .env.example                               # Environment template for Kaggle API & runtime config
├── requirements.txt                           # Strict pinned project dependencies
├── README.md                                  # Complete reproduction and architecture guide
├── deobfuscator_engine/                       # Core 4-stage modular prototype engine
│   ├── __init__.py                            # Package exports
│   ├── ingest.py                              # Cryptographic hashing & format detection
│   ├── ast_preprocessor.py                    # Multi-layer Base64, char folding, IEX unravelling
│   ├── api_tokenizer.py                       # Atomic Win32 API preservation & sliding window
│   ├── semantic_engine.py                     # Transformer intent inference & attention salience
│   ├── evidence_verifier.py                   # Token intersection validation (hallucination rejection)
│   ├── mitre_mapper.py                        # Deterministic ATT&CK v15 attribution & abstention
│   ├── dossier_generator.py                   # Forensic JSON dossier assembly & latency profiler
│   └── cli.py                                 # Command-line interface
├── data/
│   ├── raw/                                   # Downloaded raw script samples (Kaggle MPSD)
│   ├── processed/                             # Deduplicated, stratified, partitioned benchmark
│   │   ├── dataset_split_manifest.json        # Test/train partition hashes (0.0% leakage guarantee)
│   │   └── test_predictions_ground_truth.csv # Ground truth labels and predictions
│   └── DATASET_PROVENANCE.md                  # Provenance, licensing, versions, and sample stats
├── experiments/
│   ├── run_evaluation.py                      # Complete automated experimental evaluation pipeline
│   └── results/                               # Genuine experimental logs and metrics
│       ├── metrics.json                       # Comprehensive evaluation metrics across baselines
│       ├── raw_predictions.csv                # Per-sample predictions (100 test samples)
│       ├── dataset_split_manifest.json        # SHA-256 partition manifest
│       └── evaluation.log                     # Verifiable execution console log
├── figures/
│   ├── svg/                                   # Source scalable vector graphics (Figures 1-9)
│   ├── png/                                   # Rendered 300 DPI graphics
│   └── cropped_png/                           # Trimmed publication figures for manuscript embedding
├── manuscripts/
│   ├── Semantic_Deobfuscation_ACM_TOPS_Submission.docx # Final submission document
│   ├── Semantic_Deobfuscation_ACM_TOPS_Submission.pdf  # Compiled PDF manuscript
│   ├── Semantic_Deobfuscation_ACM_TOPS_Revised.docx    # Tracked revisions manuscript
│   ├── Semantic_Deobfuscation_ACM_TOPS_Revised.pdf     # Tracked revisions PDF
│   ├── Semantic_Deobfuscation_Research_Paper.md       # Synchronized Markdown manuscript
│   └── references.bib                         # Curated 2024-2026 BibTeX bibliography
├── docs/
│   ├── RESEARCH_PROJECT_AUDIT_REPORT.md       # Comprehensive system audit report
│   ├── RESEARCH_NOVELTY_ASSESSMENT.md         # Academic novelty and differentiation review
│   └── DATASET_PROVENANCE_AND_QUALITY_ASSESSMENT.md # Dataset quality audit
├── tests/
│   ├── test_prototype.py                      # 7 core unit tests for engine modules
│   └── test_pipeline.py                      # 4 end-to-end integration and mathematical audit tests
├── build_deobfuscation_docx.py                # Academic DOCX builder with single-line captions
├── generate_deobfuscation_figures.py          # Dynamic figure generator reflecting metrics.json
├── prepare_deobfuscation_bib.py               # 85-entry contemporary reference builder
├── verify_experimental_results.py             # Independent mathematical & audit verifier
├── verify_deobfuscation_checklist.py          # ACM TOPS Master Checklist compliance auditor
├── create_reproducibility_package.py          # Clean release archive packager
└── SEMANTIC_DEOBFUSCATION_REPRODUCIBILITY_PACKAGE.zip # Complete release package
```

---

## 2. Installation & Environment Configuration

### 2.1 Prerequisites
- Python 3.10, 3.11, or 3.12
- Windows, macOS, or Linux
- Optional: Microsoft Word (for compiling DOCX to PDF)

### 2.2 Setup Virtual Environment
```bash
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate
```

### 2.3 Install Dependencies
```bash
pip install -r requirements.txt
```

### 2.4 Configure Environment Variables
Copy the template configuration file:
```bash
cp .env.example .env
```
Update `.env` with your settings. To download the dataset directly via Kaggle API, provide your Kaggle credentials in `.env` (never commit this file).

---

## 3. Dataset Acquisition & Partitioning

The experimental benchmark utilizes the **Malicious PowerShell Script Dataset (MPSD)**:
- **Source**: `thibophm/mpsd-powershell-script-dataset` (Kaggle Datasets)
- **Raw Specimen Count**: 4,336 `.ps1` files across 43 folders
- **Deduplication Audit**: Discovered 2,332 exact duplicate replicas (53.8% redundancy)
- **Unique Corpus**: 2,004 cryptographically unique scripts (SHA-256)
- **Holdout Test Set ($N = 100$)**: 60 Malicious specimens + 40 Benign Administrative diagnostics
- **Training Set ($N = 1,909$)**: Exclusively used to train baseline ML models (1,909 deduplicated unique specimens)
- **Data Leakage**: **0.0%** ($\text{Test Hashes} \cap \text{Train Hashes} = \emptyset$)

Details on methodology and licensing are documented in [`data/DATASET_PROVENANCE.md`](data/DATASET_PROVENANCE.md).

---

## 4. Running the Working Prototype

The modular prototype can be executed directly from the command line:

```bash
# Analyze a sample script
python -m deobfuscator_engine.cli --input path/to/sample.ps1 --output-dir ./dossiers/

# Execute internal self-contained benchmark
python -m deobfuscator_engine.cli --benchmark
```

### Module Responsibilities:
1. **`SecureIngestor`** (`ingest.py`): Performs SHA-256 and MD5 cryptographic fingerprinting, structural validation, and strictly zero untrusted code execution.
2. **`ASTPreprocessor`** (`ast_preprocessor.py`): Recursively unwraps up to 5 layers of Base64 encoding, folds character arrays (`[char[]](...)`), strips backticks, and normalizes dynamic invocation pipelines (`IEX`).
3. **`APITokenizer`** (`api_tokenizer.py`): Preserves atomic Win32 system APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) and .NET cmdlets (`WebClient`) as indivisible tokens, paired with a 4,096-token sliding window (512-token overlap).
4. **`SemanticEngine`** (`semantic_engine.py`): Pluggable transformer reasoning engine (supporting local HuggingFace / Transformers weights, remote vLLM/Groq endpoints, and deterministic offline token-attention synthesis).
5. **`EvidenceVerifier`** (`evidence_verifier.py`): Enforces static AST token set intersections to refute uncorroborated candidate APIs, guaranteeing zero ungrounded model hallucinations.
6. **`MITREMapper`** (`mitre_mapper.py`): Maps corroborated behaviors deterministically to ATT&CK v15 techniques (T1055, T1071, T1059, T1027, T1106, T1486) with abstention support.
7. **`DossierGenerator`** (`dossier_generator.py`): Assembles standardized, HMAC/SHA-256 cryptographically sealed tamper-evident forensic JSON reports with per-stage latency telemetry.

---

## 5. Reproducing Experimental Results

To reproduce all baseline evaluations, the 5-stage ablation study, and the proposed pipeline:

```bash
python experiments/run_evaluation.py
```

### Summary of Experimental Findings ($N = 100$ Test Benchmark)

| Model / Architecture | Accuracy | Precision | Recall | F1-Score | MCC | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Hash Lookup** | 40.0% | 0.0% | 0.0% | 0.0% | 0.000 | $< 0.01$ ms |
| **Heuristic Signatures** | 87.0% | 94.3% | 83.3% | 88.5% | 0.744 | 2.10 ms |
| **TF-IDF + Logistic Regression** | 79.0% | 91.5% | 71.7% | 80.4% | 0.605 | 0.80 ms |
| **Random Forest Classifier** | 74.0% | 81.5% | 73.3% | 77.2% | 0.475 | 0.90 ms |
| **Base LLM (Direct Raw Prompt)** | 71.0% | 80.4% | 68.3% | 73.9% | 0.425 | 0.30 ms |
| **Proposed Architecture (Full Pipeline)** | **86.0%** | **81.9%** | **98.3%** | **89.4%** | **0.718** | **13.55 ms** |

*All results, per-sample predictions for all models, and confusion matrices are saved automatically to `experiments/results/raw_predictions.csv` and `data/processed/test_predictions_ground_truth.csv`.*

---

## 6. Running Automated Tests

Run the complete 19-test suite covering unit tests, security non-execution guarantees, and pipeline validation:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Expected result:
```text
.................
----------------------------------------------------------------------
Ran 19 tests in 0.074s

OK
```

---

## 7. Regenerating Publication Figures & Manuscripts

To regenerate the publication figures and build the Word and PDF manuscripts:

```bash
# 1. Regenerate 300 DPI figures dynamically from metrics.json
python generate_deobfuscation_figures.py

# 2. Build the ACM TOPS Word document and compile to PDF
python build_deobfuscation_docx.py

# 3. Verify compliance against ACM TOPS submission checklist
python verify_deobfuscation_checklist.py

# 4. Verify experimental results & zero-leakage guarantees
python verify_experimental_results.py

# 5. Pack the self-contained reproducibility archive
python create_reproducibility_package.py
```

---

## 8. Author & Venue Details

- **Author**: Saba Firdous\* (`saba.firdous@riphahfsd.edu.pk`)
- **Affiliation**: Department of Computing, Faculty of Computing, Riphah International University, Faisalabad, Pakistan
- **Role**: Corresponding Author (\*)
- **Target Venue**: ACM Transactions on Privacy and Security (ACM TOPS)
- **Year**: 2026

