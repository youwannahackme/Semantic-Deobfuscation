# Dataset Provenance, Deduplication, and Partitioning Protocol

## 1. Overview and Provenance
- **Dataset Title**: Malicious PowerShell Scripts Dataset (MPSD)
- **Primary Source Repository**: Kaggle Datasets (`thibophm/mpsd-powershell-script-dataset`)
- **Direct Kaggle URL**: `https://www.kaggle.com/datasets/thibophm/mpsd-powershell-script-dataset`
- **Academic Ingestion Reference**: Hendler et al., *Detecting Malicious PowerShell Commands using Deep Neural Networks*, ACM AsiaCCS.
- **Licensing**: Open Source (Educational and Academic Research Use).
- **Access Protocol**: Kaggle API (`kaggle datasets download -d thibophm/mpsd-powershell-script-dataset -p ./data/raw/`).

---

## 2. Ingestion Statistics & Redundancy Discovery

A systematic SHA-256 cryptographic audit across all downloaded raw `.ps1` files revealed substantial data redundancy across the source archive:

| Metric Category | Specimen Count | Percentage of Total |
| :--- | :--- | :--- |
| **Total Downloaded Raw Files** | **4,336 scripts** | 100.0% |
| **Cryptographically Unique Specimens (SHA-256)** | **2,004 scripts** | **46.2%** |
| **Exact Duplicate Replicas** | **2,332 scripts** | **53.8%** |

> **Critical Scientific Insight**: Failure to deduplicate the raw dataset prior to train/test partitioning results in severe **data leakage** (identical scripts appearing in both train and test splits), which artificially inflates reported classification performance in naive evaluations.

---

## 3. Preprocessing and AST Normalization Pipeline

Each raw script passes through the deterministic preprocessor (`deobfuscator_engine.ast_preprocessor.ASTPreprocessor`):
1. **Multi-Layer Recursive Base64 Decoding**: Detects and unpacks nested `FromBase64String`, `-EncodedCommand`, and raw Base64 payload streams up to 5 recursive layers.
2. **Character Array and String Concatenation Folding**: Resolves split strings (e.g., `[char[]](104,116,116,112)` -> `"http"` and `'d'+'o'+'w'+'n'` -> `'down'`).
3. **Format Operator Resolution**: Normalizes format specifier strings (e.g., `("{1}{0}" -f "x","e")` -> `"ex"`).
4. **Backtick Stripping**: Removes backtick escape characters (`` ` ``) used to fragment cmdlet names.
5. **Dynamic Invocation Normalization**: Standardizes dynamic execution wrappers (`Invoke-Expression`, `IEX`, `&`, `.`, `Invoke-Command`).

---

## 4. Leak-Free Evaluation Partitioning & Composition

To ensure zero train/test contamination and rigorous scientific transparency, the dataset is partitioned as follows:

### Test Partition ($N = 100$ specimens)
Strictly isolated holdout set containing representative obfuscated and benign patterns:
- **Original Malicious MPSD Scripts ($n = 60$)**:
  - Process Injection & Memory Execution ($n = 25$): Uses `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.
  - Droppers, Stagers & Remote Ingestion ($n = 15$): Uses `System.Net.WebClient`, `DownloadFile`, `DownloadString`.
  - Layered Base64 & Dynamic `IEX` Wrappers ($n = 20$): Uses nested Base64 decoding, string concatenation folding, backtick fragmentation.
- **Original Benign MPSD Scripts ($n = 35$)**:
  - Administrative Diagnostics ($n = 20$): Active Directory, Event Log collection, WMI diagnostics.
  - Other System Utilities ($n = 15$): General utility routines.
- **Curated Enterprise Administrative Fixtures ($n = 5$)**:
  - Standardized enterprise administrative diagnostics (Active Directory user query, event log audit, disk space check, service status monitor, network ping test) added to provide clean baseline operational coverage.
- **Total Test Benchmark**: Exactly **100 specimens** (60 Malicious, 40 Benign).

### Training Partition ($N = 1,909$ specimens)
The remaining $2,004 - 95 = 1,909$ unique MPSD scripts are exclusively reserved for fitting baseline classifiers (TF-IDF + Logistic Regression, Random Forest, and heuristic signatures).

### Independent Cryptographic Leakage Audit
$$\text{Test Hashes (100)} \cap \text{Train Hashes (1,909)} = \emptyset \quad (\text{Overlap} = 0 \text{ samples}, \mathbf{0.0\%} \text{ data leakage})$$

Both hash sets are stored in `data/processed/dataset_split_manifest.json` and verified by `verify_experimental_results.py` via direct set intersection.

---

## 5. Storage Directory Structure
- **`data/raw/`**: Uncompressed raw `.ps1` files from Kaggle MPSD across categories `1` through `43`.
- **`data/processed/`**:
  - `benchmark_test_samples.json`: Complete executable payload code, SHA-256 hashes, categories, and ground-truth labels for all 100 evaluation test samples (enables full reproduction without external downloads).
  - `dataset_split_manifest.json`: Full cryptographic manifest containing sample counts, category distributions, all 100 test hashes, and all 1,909 train hashes.
  - `test_predictions_ground_truth.csv`: Evaluated test specimen ground truth and pipeline predictions.
