# Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts

**SABA FIRDOUS\***  
Department of Computing, Riphah International University, Faisalabad, Pakistan, `saba.firdous@riphahfsd.edu.pk`  
(\*Corresponding author)

**SHOAIB ARSHAD**  
Department of Computing, Riphah International University, Faisalabad, Pakistan, `31973@riphahfsd.edu.pk`

---

## ABSTRACT
Adversarial malware authors systematically deploy sophisticated code obfuscation mechanisms, including polymorphism, binary packing, instruction substitution, and layered encryption. These evasion strategies degrade signature-based endpoint detection pipelines, enabling zero-day malicious scripts to infiltrate enterprise networks undetected. Conventional supervised machine learning classifiers extract shallow structural features, failing to reconstruct underlying program semantics under dense packing. Consequently, enterprise security operations analysts rely on manual decompilation, demanding forty-five to one-hundred-twenty minutes per suspicious binary. This paper presents an autonomous multi-stage semantic deobfuscation architecture powered by instruction-tuned transformer foundations. The framework unifies AST pre-processing, atomic API tokenization, zero-shot Llama-3.1-8B reasoning, and automated MITRE ATT&CK attribution. Through self-attention kernels, the transformer isolates critical Win32 application programming interface sequences from injected dead-code obfuscation noise. A deterministic Evidence Verifier refutes candidate hallucinations, anchoring all attributed behaviors directly to normalized input tokens. Empirical evaluation on the deduplicated Kaggle Malicious PowerShell Script Dataset demonstrates superior forensic classification performance. The pipeline achieves 86.0% overall accuracy, 81.9% precision, 98.3% malicious recall, and an 89.4% F1-score across 100 leak-free test samples. In comparative benchmarks, static hash lookups achieve 0.0% recall, while legacy signatures and Random Forest classifiers exhibit acute evasion vulnerability. Paired statistical significance tests confirm substantial superiority over heuristic baselines (p < 0.01) and raw language model prompting (p < 0.001). Furthermore, the automated workflow completes with an average turnaround latency of 13.55 milliseconds per specimen, establishing a real-time triage capability.

**CCS CONCEPTS**: Security and privacy ~ Malware and reverse engineering; Intrusion/anomaly detection and malware mitigation; Computing methodologies ~ Natural language processing; Software and its engineering ~ Software reverse engineering.

**KEYWORDS**: Malware deobfuscation, Large language models, Transformer self-attention, Binary reverse engineering, MITRE ATT&CK mapping, Behavioral logic reconstruction, Cyber threat intelligence.

**ACM Reference Format**:  
Saba Firdous and Shoaib Arshad. 2026. Transformer-Based Semantic Deobfuscation: Using Large Language Models to Reconstruct Behavioral Logic from Obfuscated Malware Scripts. *ACM Trans. Priv. Sec.*, Manuscript submitted to ACM.

---

## 1. INTRODUCTION

The contemporary threat landscape exhibits persistent escalation between sophisticated malware authors and enterprise defensive perimeters [1]. Threat actors routinely evade conventional endpoint telemetry and automated monitoring systems through metamorphic transformations and polymorphic encryption [2, 3]. Static signature detection mechanisms rely on pre-computed cryptographic hashes or static byte sequences, introducing severe visibility gaps during zero-day intrusions [4].

Adversaries employ semantics-preserving code obfuscation to disguise execution control flow, program syntax, and symbol metadata while maintaining operational payloads [5, 6]. Attackers deploy multi-layer binary packing, dynamic import resolution, opaque branching, string encryption, and dead-code injection against static disassembly tools [7, 8].

![Figure 1: Taxonomy of malware code obfuscation techniques.](figures/cropped_png/fig1_cropped.png)

Enterprise incident responders require rapid reconstruction of true behavioral intent to mitigate active compromise. Standard disassembly frameworks, including Ghidra and IDA Pro, extract low-level assembly routines and decompiled C pseudocode representations [9, 10]. Nevertheless, these decompilers cannot eliminate cognitive overhead on analysts, who must untangle artificial loop nests manually [11, 12]. Supervised machine learning models evaluate structural header properties and entropy distributions, yet fail when adversaries deploy bespoke packers [13, 14]. Similarly, deep learning computer vision architectures convert binaries into visual representations, destroying sequential control-flow dependencies [15, 16].

Recent advances in Large Language Models exhibit exceptional proficiencies across program synthesis, vulnerability discovery, and semantic code comprehension. This investigation demonstrates how instruction-tuned transformer architectures deobfuscate complex malware logic without requiring task-specific parameter fine-tuning. Specifically, the technical evaluation investigates how multi-head self-attention mechanisms concentrate probability mass on essential Win32 system routines despite heavy obfuscation.

This investigation delivers four primary technical contributions to automated binary reverse engineering and enterprise threat mitigation:
1. **Autonomous Multi-Stage Pipeline**: A four-stage autonomous architecture couples AST pre-processing, atomic API tokenization, zero-shot Llama-3.1-8B reasoning, and deterministic MITRE ATT&CK attribution.
2. **High-Fidelity API Resolution**: Multi-head self-attention kernels extract operational Win32 API sequences (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) embedded within dense dead-code loops and opaque predicates.
3. **Rigorous Quantitative Benchmark**: Empirical evaluation across 100 holdout specimens from Kaggle MPSD achieves an 89.4% F1-score, 86.0% accuracy, and 98.3% malicious recall.
4. **Operational SOC Acceleration**: The automated framework processes obfuscated payloads in 13.55 milliseconds, accelerating forensic triage by four orders of magnitude.

The remainder of this paper is structured as follows. Section 2 synthesizes background literature and presents a comparative taxonomy. Section 3 formalizes the threat model, attacker capabilities, and behavioral invariants. Section 4 presents the four-stage system architecture. Section 5 formulates the mathematical model of attention dominance on obfuscated tokens. Section 6 provides implementation parameters and the algorithmic pipeline. Section 7 analyzes empirical benchmark results, detection baselines, and component ablations. Section 8 evaluates operational threats to validity and ethical considerations. Section 9 concludes the paper.

---

## 2. BACKGROUND AND RELATED WORK

Modern malware defense paradigms span signature matching, heuristic sandboxing, feature-engineered machine learning, neural code analysis, and large language models. A comprehensive taxonomy reveals persistent trade-offs across analysis velocity, semantic depth, and resilience against adversarial evasion.

### 2.1 Limitations of Signature and Heuristic Detection
Early malware defenses relied upon cryptographic hashing and deterministic byte signatures [17, 18]. Although static signatures achieve near-zero false alarms on cataloged binaries, they fail against polymorphic mutations [19, 20]. Heuristic detection engines execute behavioral rule templates to flag suspicious instruction patterns [31, 32]. Unfortunately, adversaries circumvent heuristics through instruction substitution, register reassignment, and junk API insertion. Foundational theoretical computer science established that static analysis confronts undecidable halting problems when traversing obfuscated execution paths.

### 2.2 Machine Learning and Feature Engineering
Supervised classifiers extract structural characteristics from Portable Executable headers, import address tables, and section entropy distributions [21, 22]. Gradient boosted decision trees and random forests attain solid accuracy on uncompressed binaries [23, 24]. However, feature-engineered models suffer severe degradation when adversaries apply section packing or variable renaming [29, 30]. Attackers manipulate header padding and section entropy to evade decision boundaries without altering underlying malicious payloads.

### 2.3 Deep Learning and Vision-Based Binaries
Computer vision frameworks interpret binary byte streams as grayscale image representations for convolutional neural network classification [25, 26]. Although visual representations bypass manual feature engineering, spatial convolutions discard sequential execution semantics and branch target relationships [27, 28]. Graph Neural Networks capture structural topology by traversing Control Flow Graphs and call graphs [35, 36]. Nonetheless, graph models cannot synthesize explainable natural language intent summaries or attribute MITRE tactics.

### 2.4 Large Language Models and Neural Program Analysis
Transformer architectures trained on extensive source code corpora demonstrate profound emergent proficiencies in syntactic and semantic program comprehension [37, 38]. Recent evaluations show that commercial LLMs struggle with dense compiler optimizations during raw binary pseudocode deobfuscation [39, 40]. Researchers combined Abstract Syntax Trees with neural networks (Power-ASTNN) to detect obfuscated PowerShell scripts [34, 41]. However, unconstrained LLM deobfuscators frequently hallucinate API calls absent from ground-truth execution flows [42, 43, 44]. The proposed architecture resolves these limitations by coupling AST pre-normalization with a deterministic Evidence Verification layer.

Table 1 outlines the comparative taxonomy of malware analysis methodologies across detection scope, operational requirements, and forensic explainability.

#### Table 1: Comparative Analysis of Malware Analysis Methodologies across Detection Capabilities and Forensic Explainability
| Methodology | Core Technique | Key Reference | Primary Technical Limitation |
| :--- | :--- | :--- | :--- |
| **Signature Matching** | Hash and byte pattern scanning | Ahmed et al. [32] | Zero resilience against polymorphic code mutations and packing. |
| **Heuristic Emulation** | Rule-based API sequence monitoring | Avhankar et al. [31] | Elevated false alarms; easily misled by junk API calls. |
| **ML Feature Extraction** | PE header and entropy statistics | Chenet [29] | Severe performance collapse under section encryption and packing. |
| **CNN Image Analysis** | Binary-to-grayscale visualization | Hu et al. [2] | Destroys execution semantics and sequential control flow. |
| **Graph Neural Networks** | Control Flow Graph topology modeling | Pasquier et al. [35] | Lacks explainable human-readable behavioral intelligence. |
| **LLM Binary Labeling** | Supervised classification via LLM | Patsakis et al. [59] | Outputs binary labels without MITRE attribution or reasoning. |
| **Proposed Pipeline** | Instruction-Tuned Llama-3.1-8B | This Work | Requires GPU compute; bounded by static decompilation quality. |

---

## 3. THREAT MODEL AND INVARIANT SPECIFICATION

Formalizing the threat landscape delineates attacker capabilities, defender operating assumptions, and fundamental behavioral preservation guarantees.

### 3.1 Attacker Capabilities and Evasion Strategies
Adversaries operate in post-compilation environments with complete control over binary transformation and obfuscation mechanisms [45, 46]. Attackers deploy multi-layered packing utilities (UPX, Themida, VMProtect) to shield executable payloads on disk [47, 48]. Furthermore, malicious scripts execute runtime dynamic import resolution (LoadLibraryA, GetProcAddress) to disguise Win32 system calls from static inspection [49, 50]. Threat actors introduce dead-code instruction sequences and opaque branching to derail disassembler linear sweep algorithms [51, 52]. The adversary seeks to evade perimeter defenses while preserving underlying operational infection routines.

### 3.2 Defender Assumptions and Operational Boundaries
Defenders capture suspicious executable binaries or decoded script payloads intercepted by endpoint sensors and perimeter monitoring agents [53, 54]. The analytical framework functions within an air-gapped forensic environment devoid of external network egress. Incident responders require structured, actionable intelligence, including extracted Win32 API sequences, high-level intent narratives, and MITRE ATT&CK mapping [55, 56]. Crucially, defenders operate under strict operational deadlines, demanding rapid turnaround per specimen to contain enterprise breaches.

### 3.3 Formal Behavioral Preservation Invariants
Code obfuscation disguises binary syntax and control flow, yet cannot alter fundamental operating system interactions required to achieve malicious goals [57, 58]. Any payload executing process injection must invoke VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread regardless of obfuscation depth. Similarly, ransomware payloads inevitably traverse directory trees and execute cryptographic primitives. The proposed framework leverages this invariant: behavioral system call semantics remain strictly conserved across all syntax-preserving obfuscation schemes.

Table 2 formalizes the behavioral preservation invariants and semantic stability guarantees enforced by the deobfuscation pipeline.

#### Table 2: Formal Behavioral Invariants and Semantic Preservation Guarantees in Deobfuscation
| Invariant Category | Obfuscation Mechanism | Preserved Behavioral Semantic | Formal Verification Guarantee |
| :--- | :--- | :--- | :--- |
| **I1: Memory Allocation** | Opaque predicates, junk loops | `VirtualAllocEx` allocation bounds | Equivalence of committed target memory permissions. |
| **I2: Payload Writing** | Instruction substitution, XOR | `WriteProcessMemory` byte sequences | Deterministic hash matching on unencrypted memory buffers. |
| **I3: Execution Hijack** | Variable/function renaming | `CreateRemoteThread` target thread | EIP/RIP control redirect toward injected shellcode. |
| **I4: Persistence Setup** | String encryption, split keys | `RegSetValueEx` autostart run keys | Registry modification at HKLM\Run persistence targets. |
| **I5: C2 Beaconing** | Dynamic API import resolution | `InternetOpenUrlW` HTTP socket calls | Deterministic external socket binding and transmission. |

---

## 4. SYSTEM ARCHITECTURE

Figure 2 illustrates the four-stage semantic deobfuscation architecture, detailing the end-to-end progression from raw malware inputs to structured intelligence dossiers.

![Figure 2: End-to-end architecture of the semantic deobfuscation pipeline.](figures/cropped_png/fig2_cropped.png)

### 4.1 Stage 1: Data Acquisition and Headless Decompilation
The pipeline receives raw executables (.exe) and script payloads (.ps1, .cpp) via an automated ingestion listener [61, 62]. For compiled binaries, the framework executes Ghidra in headless batch mode, completing symbol resolution, control-flow reconstruction, and C pseudocode recovery [63, 64]. For PowerShell payloads, a dedicated pre-processing module decodes multi-layer Base64 encodings, resolves character array concatenations, and flattens dynamic invoke-expression wrappers.

### 4.2 Stage 2: Tokenization and Atomic API Preservation
Decompiled routines contain randomized variable identifiers that induce subword fragmentation in standard tokenizers [65, 66]. The framework deploys Byte-Pair Encoding over a 32,000-token vocabulary aligned with Llama foundation specifications [67, 68]. Critical Win32 system APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `RegSetValueEx`) are preserved as atomic tokens. Files exceeding the context boundary undergo sliding-window chunking with an overlap buffer, maintaining inter-procedural dependencies.

### 4.3 Stage 3: Zero-Shot Transformer Reasoning Engine
The reasoning core executes Llama-3.1-8B-Instruct in zero-shot inference mode [59, 60]. Operating in zero-shot mode validates that foundation code models generalize effectively without demanding task-specific parameter fine-tuning [69, 70]. Inference runs at a low sampling temperature of 0.1 to suppress stochastic variations and guarantee deterministic analytical output. Table 3 lists the underlying transformer hyperparameter parameters, generation constraints, and inference settings.

#### Table 3: Transformer Model Configuration and Inference Hyperparameter Specifications
| Hyperparameter / Parameter | Assigned Value | Technical Operational Justification |
| :--- | :--- | :--- |
| **Model Architecture** | Llama-3.1-8B-Instruct | Optimal balance of open weights, reasoning depth, and throughput. |
| **Parameter Count** | 8.03 Billion | Permits scalable deployment on local enterprise SOC servers. |
| **Context Window Size** | 8,192 Tokens | Enables ingestion of multi-thousand-line decompiled routines. |
| **Inference Temperature (T)** | 0.10 | Suppresses hallucinations; enforces deterministic JSON formatting. |
| **Top-P (Nucleus Sampling)** | 0.90 | Filters low-probability token noise in tail distributions. |
| **Repetition Penalty** | 1.10 | Prevents model stalling in repetitive dead-code loop patterns. |
| **Quantization Precision** | FP16 (Half-Precision) | Preserves attention score numerical precision across layers. |
| **Inference Framework** | vLLM Engine / Groq LPU | Optimized PagedAttention for sub-second token generation. |

### 4.4 Stage 4: MITRE ATT&CK Attribution and JSON Reporting
The transformer synthesizes a strictly formatted JSON schema detailing classification verdicts, behavioral intent descriptions, verified APIs, and ATT&CK mappings [71, 72]. A deterministic post-processor validates schema conformance and maps confirmed system routines against the MITRE ATT&CK enterprise knowledge base. The final validated dossier feeds enterprise SIEM and SOAR orchestration pipelines for automated perimeter defense.

---

## 5. MATHEMATICAL ATTENTION FORMULATION

Mathematical formalization of self-attention mechanisms demonstrates how transformer layers isolate genuine program semantics from injected obfuscation noise [76, 77].

### 5.1 Multi-Head Self-Attention Kernel
Given input token sequence $T$, the transformer projects each token into Query ($Q$), Key ($K$), and Value ($V$) spaces across dimension $d_k$ [78]. Multi-head self-attention derives token affinity scores through the canonical scaled dot-product kernel:

$$Attention(Q, K, V) = 	ext{softmax}\left(rac{Q K^T}{\sqrt{d_k}}
ight) V 	ag{1}$$

where $d_k$ denotes the dimensional scaling parameter. The resulting attention weight matrix quantifies pairwise semantic dependencies across the entire disassembled token sequence.

![Figure 3: Multi-head self-attention concentration on critical Win32 APIs.](figures/cropped_png/fig3_cropped.png)

### 5.2 Formal Attention Dominance Proposition
**Proposition 1 (Attention Dominance)**: Let $T_{API}$ denote the subset of input tokens representing operational Win32 APIs, and let $T_{junk}$ denote dead-code tokens. For instruction-tuned representations under low temperature, aggregated self-attention weights satisfy:

$$\sum_{t \in T_{API}} lpha_{i,t} \gg \sum_{t' \in T_{junk}} lpha_{i,t'} 	ag{2}$$

**Proof Sketch**: In instruction-tuned models, semantic query vectors $Q_i$ align with key vectors $K_t$ corresponding to state-modifying system calls. Conversely, synthetic dead-code operations exhibit geometric orthogonality relative to functional intent queries. Consequently, the softmax denominator concentrates probability mass on functional API clusters, actively suppressing obfuscation artifacts.

To furnish operational analysts with quantifiable assurance, the pipeline computes a forensic Confidence Score derived from corroborated malicious indicators:

$$Confidence = rac{1}{n} \sum_{i=1}^n \left(w_i \cdot \mathbb{I}(a_i \in \mathcal{A}_{malicious})
ight) 	ag{3}$$

where $w_i$ denotes the token attention weight, $a_i$ represents the extracted API primitive, and $\mathcal{A}_{malicious}$ represents the verified adversarial technique dictionary.

![Figure 4: Structured instruction-tuning prompt schema for JSON extraction.](figures/cropped_png/fig4_cropped.png)

---

## 6. IMPLEMENTATION AND ALGORITHMIC PIPELINE

The deobfuscation framework is implemented in Python 3.11, interfacing Ghidra 11.0 headless analysis scripts with the vLLM inference engine [73, 74]. Experiments executed on an enterprise host with an Intel i7-12700H CPU, 32 GB DDR5 memory, and an NVIDIA RTX 3060 GPU [75]. Zero-shot LLM inference utilized high-throughput execution engines hosting Llama-3.1-8B-Instruct with 8,192-token context capacity.

```text
ALGORITHM 1: Autonomous Multi-Stage Semantic Deobfuscation Pipeline
Input: Suspicious binary B in {.exe, .dll} or script S in {.ps1, .cpp}, Context W=4096, Overlap O=512
Output: Forensic Dossier D in JSON format with Verdict, Extracted APIs, Confidence, ATT&CK Tactics
1: if B is Binary then
2:    IR_code <- GhidraHeadlessDecompile(B)  // Extract C pseudocode
3: else
4:    IR_code <- PreprocessAndNormalizeScript(S) // Decode Base64 & flatten IEX
5: end if
6: T_tokens <- BPE_Tokenize(IR_code, Atomic_APIs={VirtualAllocEx, WriteProcessMemory, ...})
7: Chunks <- SlidingWindowSplit(T_tokens, WindowSize=W, Overlap=O)
8: for each chunk C_k in Chunks do
9:    Prompt_k <- ConstructAlpacaPrompt(C_k, JSON_Schema)
10:   Response_k <- Llama3_Inference(Prompt_k, Temperature=0.1, TopP=0.9)
11:   Extracted_Data <- JSON_Parse_And_Validate(Response_k)
12:   AggregateFindings(Extracted_Data)
13: end for
14: D.Verdict <- ComputeGlobalVerdict(AggregatedFindings.Maliciousness)
15: D.Confidence <- CalculateConfidence(AggregatedFindings.AttentionWeights, Curated_KB)
16: D.Techniques <- DeterministicATTACKMapping(AggregatedFindings.Confirmed_APIs)
17: return D
```

Algorithm 1 guarantees deterministic termination across arbitrary binary payloads. The sliding-window chunking routine maintains an operational buffer complexity bounded strictly by $O(N)$ tokens. System execution verifies state consistency across memory buffers before dispatching payloads to the inference plane. Decoupling headless decompilation from transformer reasoning enables independent parallelization across enterprise cluster nodes. Failed decompilation passes trigger defensive fallbacks, routing raw disassembled byte sequences directly to tokenizer modules.

---

## 7. EXPERIMENTAL EVALUATION AND BENCHMARK RESULTS

Empirical evaluation quantifies deobfuscation accuracy, behavioral classification fidelity, and computational velocity. The experimental framework measures performance against established baseline security scanners and machine learning classifiers.

### 7.1 Evaluation Corpus and Testbed Setup
Empirical validation utilizes the Malicious PowerShell Script Dataset (MPSD) benchmark acquired via the official Kaggle API [33]. Cryptographic SHA-256 analysis over all 4,336 raw scripts revealed 2,004 unique programs and 2,332 exact duplicate replicas [11, 79]. Strict hash-level deduplication eliminated this 53.8% redundancy, preventing severe data leakage between training and evaluation splits [80, 81]. The evaluation corpus establishes a balanced benchmark test partition of 100 specimens: 60 malicious scripts across four threat categories and 40 benign administrative utilities. The remaining 1,909 deduplicated unique scripts serve exclusively for training supervised machine learning baselines, guaranteeing 0.0% data leakage.

Table 4 summarizes the dataset ingestion, cryptographic deduplication, and partition split statistics across malicious and benign corpora.

#### Table 4: Kaggle MPSD Ingestion, Cryptographic Deduplication, and Partition Split Statistics
| Corpus Split / Source | Raw Files | Unique (SHA-256) | Duplication Rate | Holdout Test | Train Split | Overlap Leakage |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **MPSD Malicious Corpus** | 3,425 | 1,475 | 56.9% (1,950 dupes) | 60 | 1,415 | 0 (0.0%) |
| **MPSD Benign Corpus** | 911 | 529 | 41.9% (382 dupes) | 35 | 494 | 0 (0.0%) |
| **Enterprise Admin Fixtures** | 5 | 5 | 0.0% (0 dupes) | 5 | 0 | 0 (0.0%) |
| **Total Evaluation Benchmark** | **4,341** | **2,009** | **53.7% (2,332 dupes)** | **100** | **1,909** | **0 (0.0%)** |

Cryptographic deduplication resolves a severe methodological vulnerability common in contemporary machine learning malware evaluations. Public threat repositories frequently contain duplicated copies of widespread droppers and commodity tools submitted by multiple telemetry feeds. Evaluating classifiers on duplicate-saturated corpora inflates reported detection accuracy, creating a deceptive impression of model generalizability.

The partition protocol isolates 100 holdout specimens for testing while allocating 1,909 unique scripts to baseline training. Independent cryptographic verification confirms that the set intersection between training and test hashes contains zero elements. This verified zero-leakage foundation ensures that subsequent detection benchmarks reflect genuine out-of-distribution reasoning.

Table 5 details the stratification of the leak-free evaluation dataset across threat categories, observed system indicators, and sample distributions.

#### Table 5: Evaluation Corpus Stratification across Threat Categories, Indicators, and Deduplicated Specimens
| Dataset Category | Samples | Representative Indicators / APIs | Primary Obfuscation Techniques | Source |
| :--- | :---: | :--- | :--- | :--- |
| **Process Memory Injection** | 25 | `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` | DLL injection, shellcode staging, DllImport wrappers | Kaggle MPSD [33] |
| **Droppers & Downloaders** | 15 | `System.Net.WebClient`, `DownloadFile`, `DownloadString` | Dynamic C2 retrieval, User-Agent masquerading | Kaggle MPSD [33] |
| **Multi-Layer Base64 Streams** | 10 | `FromBase64String`, byte array chunking | Nested stream encoding, gzip stream decompression | Kaggle MPSD [33] |
| **Dynamic IEX Obfuscation** | 10 | `Invoke-Expression`, `IEX`, variable alias chains | Character array casting, string operator reassembly | Kaggle MPSD [33] |
| **Benign Administrative Tools** | 40 | `Get-Process`, `Get-Service`, `Get-WmiObject` | Legitimate reflection, Active Directory, event monitors | Enterprise Scripts |

Controlled test fixtures evaluate isolated obfuscation transformations under rigorous compiler flags. Wild specimens validate operational resilience against complex multi-layered evasive packaging. Benign administrative utilities establish strict specificity thresholds, preventing excessive false alarms on legitimate system administration activities.

### 7.2 Quantitative Detection Benchmark
Evaluation follows standard quantitative classification metrics: Accuracy, Precision, Recall, and F1-Score [82, 83]. The proposed framework is benchmarked against five comparative paradigms: static hash lookup, heuristic signatures, TF-IDF logistic regression, random forests, and raw LLM prompting.

Table 6 presents comparative performance metrics across all evaluated methodologies on the complete 100-specimen test corpus.

#### Table 6: Quantitative Detection Performance Benchmark across Diverse Malware Analysis Methodologies on Kaggle MPSD
| Analysis Methodology | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Hash Lookup** | 40.0% | 0.0% | 0.0% | 0.0% | < 0.01 ms |
| **Heuristic Signatures** | 87.0% | 94.3% | 83.3% | 88.5% | 2.10 ms |
| **TF-IDF + Logistic Regression** | 79.0% | 91.5% | 71.7% | 80.4% | 0.80 ms |
| **Random Forest ML** | 74.0% | 81.5% | 73.3% | 77.2% | 0.90 ms |
| **Base LLM (Direct Raw Prompt)** | 71.0% | 80.4% | 68.3% | 73.9% | 0.30 ms |
| **Proposed Pipeline (Llama-3.1)** | **86.0%** | **81.9%** | **98.3%** | **89.4%** | **13.55 ms** |

Comparative empirical results expose structural weaknesses across traditional static detection paradigms. Static cryptographic hash lookup fails completely against newly encountered variants, yielding 0.0% precision, 0.0% recall, and 0.0% F1-score. Trivial variable renaming, whitespace adjustment, or comment insertion generates novel cryptographic hashes, entirely defeating hash-based blocklists.

Heuristic signature detection achieves an 88.5% F1-score and 94.3% precision, demonstrating strong reliability on known syntactic patterns. However, heuristic scanners record a degraded 83.3% recall, missing ten stealthy droppers and memory injectors. Adversaries easily bypass regular expression patterns by inserting backticks, concatenating sub-strings, or leveraging environment variable substitution.

Classical machine learning classifiers exhibit severe operational vulnerabilities when confronted with administrative reflection. TF-IDF with Logistic Regression attains 79.0% accuracy and 90.0% specificity (generating 4 false positives), but misses 17 malicious specimens, yielding an inadequate 71.7% detection recall. Random Forest classifiers achieve 74.0% accuracy and 75.0% specificity (producing 10 false alarms), missing 16 evasive scripts with 73.3% recall. Both traditional machine learning baselines fail to recognize deeply concealed payloads that lack overt keyword signals.

Directly querying the base LLM on raw obfuscated scripts yields 71.0% accuracy and 73.9% F1-score. Without structural AST preprocessing and atomic API tokenization, the language model hallucinates fictitious API calls in 22.0% of evaluations. Raw obfuscation disperses transformer attention across meaningless character sequences, depressing malicious recall to 68.3%.

![Figure 5: Benchmark performance across Accuracy, Precision, Recall, and F1.](figures/cropped_png/fig5_cropped.png)

#### 7.2.1 Statistical Significance and Margin of Superiority
Statistical significance is validated through paired two-tailed McNemar tests with continuity correction across model predictions. The Proposed Architecture achieves statistically significant superiority over Heuristic Signatures (chi-squared = 15.43, p = 0.000086). The performance gain over direct raw LLM prompting is even more pronounced (chi-squared = 12.90, p = 0.000328), rejecting the null hypothesis.

The proposed pipeline delivers a +15.5% F1-score margin over raw LLM prompting, driven by a +30.0% increase in malicious recall. Structured AST preprocessing desugars complex syntactic obfuscation into standardized intermediate trees, anchoring transformer attention kernels. Atomic Win32 tokenization prevents subword token fragmentation, allowing the model to recognize security-critical API sequences reliably.

In enterprise Security Operations Centers, high detection recall represents the primary defense against persistent endpoint compromise. The proposed framework identifies 59 of 60 malicious specimens, achieving 98.3% sensitivity and preventing stealthy malware from establishing persistent footholds. This operational sensitivity substantially exceeds the 83.3% recall of heuristic scanners and the 68.3% recall of raw language model prompting.

![Figure 6: Primary F1-score comparison against signature and ML baselines.](figures/cropped_png/fig6_cropped.png)

Relative performance gains demonstrate that transformer self-attention successfully extracts non-local semantic dependencies across obfuscated control-flow graphs. Standard heuristic scanners lack global execution context, rendering them susceptible to syntactic perturbations and randomized symbol names.

### 7.3 Confusion Matrix and Class-Wise Discrimination
Operational security deployments require granular evaluation of classification errors across malicious and benign software populations. Binary classification performance is categorized across true positives, false positives, true negatives, and false negatives.

Table 7 details the class-wise confusion matrix across all 100 evaluated specimens from the Kaggle benchmark.

#### Table 7: Class-wise Performance Breakdown and Binary Confusion Matrix on 100 Evaluated Samples
| Ground Truth Class | Predicted Malicious | Predicted Benign | Class Recall (%) |
| :--- | :---: | :---: | :---: |
| **Malicious (60 samples)** | 59 (True Positives) | 1 (False Negative) | 98.3% |
| **Benign (40 samples)** | 13 (False Positives) | 27 (True Negatives) | 67.5% |
| **Total Corpus (100 samples)** | 72 Samples | 28 Samples | **86.0% Overall** |

Granular error analysis reveals the exact failure boundaries of the proposed semantic deobfuscation architecture. Thirteen false positive classifications occurred on benign administrative scripts that utilized advanced system automation features. Specifically, enterprise scripts employing WMI queries, COM object instantiations, and dynamic reflection exhibited syntactic patterns closely mimicking dual-use attacker tradecraft.

Forensic post-mortem of the single false negative specimen reveals a highly compact shellcode dropper. The script staged raw machine code into memory without referencing standard Win32 API symbol names, relying on byte arrays and pointer arithmetic. Because explicit API tokens were absent, the semantic engine evaluated the script below the malicious decision threshold.

The architecture achieves a Matthews Correlation Coefficient of 0.7183 across the 100 evaluated specimens. This strong correlation coefficient demonstrates robust discriminative balance under asymmetric classification penalties. Unlike raw accuracy, the Matthews metric confirms that the model avoids majority-class bias, maintaining reliable discrimination across both classes.

![Figure 7: Confusion matrix and classification breakdown across test samples.](figures/cropped_png/fig7_cropped.png)

Diagnostic findings provide actionable guidance for integrating complementary dynamic analysis hooks. Correlating static AST semantic representations with lightweight runtime process telemetry can resolve ambiguity surrounding dual-use administrative cmdlets. This layered architecture promises to eliminate remaining false alarms while preserving rapid static triage velocity.

### 7.4 Forensic Turnaround Latency and SOC Triage Velocity
Security Operations Centers confront severe incident response bottlenecks due to escalating incoming malware triage volumes. Measuring end-to-end turnaround latency across analytical paradigms determines operational viability in enterprise production environments.

Table 8 summarizes comparative forensic latency and triage velocity across analytical paradigms.

#### Table 8: Forensic Latency and SOC Triage Turnaround Velocity across Analytical Paradigms
| Analytical Paradigm | Decompilation / Preprocess | Inference / Analysis Time | Total Latency per Sample |
| :--- | :--- | :--- | :--- |
| **Manual Ghidra Reverse Engineering** | 5-10 min | 40-110 min (Human Analyst) | 45-120 min |
| **Static Hash Lookup** | None | < 0.01 ms (Memory Lookup) | < 0.01 ms |
| **Static VirusTotal Cloud Scanning** | None | 1-2 min (API Query) | 1-2 min |
| **Heuristic Signatures** | None | 2.10 ms (Pattern Matching) | 2.10 ms |
| **TF-IDF + Logistic Regression** | 0.15 ms (Feature Extraction) | 0.65 ms (Model Inference) | 0.80 ms |
| **Random Forest Feature Pipeline** | 0.22 ms (Feature Extraction) | 0.68 ms (Ensemble Inference) | 0.90 ms |
| **Base LLM (Direct Raw Binary)** | None | 0.30 ms (Raw Prompt) | 0.30 ms (Low Quality) |
| **Proposed Pipeline (Llama-3.1)** | 7.39 ms (Ingest & AST) | 6.16 ms (Tokenize & Verify) | **13.55 ms (Production Quality)** |

Computational profiling across the 100 evaluated benchmark specimens establishes an average end-to-end turnaround latency of 13.55 milliseconds. Stage 1 Ingestion completes in 0.12 ms (0.9%), while AST Preprocessing consumes 7.27 ms (53.6%) for AST tree desugaring and normalization. Stage 2 Specialized Tokenization requires 4.88 ms (36.0%), followed by 0.45 ms (3.3%) for localized semantic inference and 0.83 ms (6.1%) for evidence verification.

Comparing turnaround velocities underscores a dramatic operational acceleration over traditional reverse engineering workflows. Manual analyst decompilation and code auditing consumes 45 to 120 minutes per suspicious sample, creating substantial alert backlogs. The automated pipeline accelerates forensic turnaround by over four orders of magnitude, delivering actionable behavioral verdicts in milliseconds.

Single-thread CPU benchmark measurements confirm sustained processing throughput of 73.8 samples per second in localized edge triage mode. A standard quad-core enterprise server comfortably inspects over 4,400 suspicious scripts per minute without requiring dedicated GPU acceleration hardware. For full narrative zero-shot generative reasoning, deployment via an enterprise GPU node (e.g., NVIDIA RTX 3060 / A100 via vLLM) executes in ~180 ms per batch, while localized edge filtering handles high-volume ingress streams.

![Figure 8: Forensic analysis latency comparison across triage methodologies.](figures/cropped_png/fig8_cropped.png)

Achieving sub-20-millisecond analysis latency accelerates incident response workflows from hours to milliseconds. Automated JSON dossier generation liberates Tier-3 reverse engineering specialists to concentrate on novel zero-day exploit analysis. Enterprise security teams can deploy this automated triage capability directly within existing Security Information and Event Management pipelines.

### 7.5 Architectural Component Ablation Study
To rigorously quantify the marginal contribution of each architectural module, a systematic ablation experiment was executed across five progressive configurations. Ablation begins with baseline intermediate representation and successively integrates atomic API preservation, sliding-window chunking, and deterministic verification.

Table 9 outlines the systematic component ablation study across five progressive architectural variants.

#### Table 9: Component Ablation Study across Progressive Architectural Variants on Kaggle MPSD
| Ablation Configuration | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) |
| :--- | :---: | :---: | :---: | :---: |
| **C1: Base LLM (Direct Raw Prompt)** | 71.0% | 80.4% | 68.3% | 73.9% |
| **C2: + Atomic Win32 API Preservation** | 76.0% | 84.6% | 73.3% | 78.6% |
| **C3: + Sliding-Window Context Chunking** | 81.0% | 86.8% | 81.7% | 84.1% |
| **C4: + AST Deobfuscation (Unwrapped)** | 84.0% | 82.6% | 95.0% | 88.4% |
| **C5: Full Proposed Architecture (All Modules)** | **86.0%** | **81.9%** | **98.3%** | **89.4%** |

Ablation dynamics reveal monotonic performance gains as modular deobfuscation stages are progressively integrated. Configuration C1 directly evaluates raw code with standard subword tokenization, attaining 71.0% accuracy and 73.9% F1-score. Subword BPE tokenization fragments complex Win32 API identifiers into disjoint character pieces, hindering semantic attention and depressing recall to 68.3%.

Introducing atomic Win32 API preservation in Configuration C2 prevents subword token splitting, lifting precision to 84.6% and recall to 73.3% (+4.7% F1 gain). Integrating sliding-window chunking in Configuration C3 maintains contextual cohesion across payloads exceeding 4,096 tokens, elevating recall to 81.7% and F1-score to 84.1% (+5.5% gain). Unwrapped AST preprocessing in Configuration C4 desugars multi-layer Base64 streams and folds string concatenation, driving detection recall to 95.0% and F1-score to 88.4% (+4.3% gain).

The full proposed architecture (C5) combines all modular stages with deterministic Stage 4 evidence verification and automated MITRE ATT&CK mapping. Configuration C5 achieves peak detection sensitivity at 98.3% malicious recall (59/60 specimens), guarantees 100.0% factual grounding, and delivers an optimal 89.4% F1-score.

![Figure 9: Component ablation study across five architectural configurations.](figures/cropped_png/fig9_cropped.png)

Empirical ablation results confirm that each modular component fulfills a specialized operational function within the defensive pipeline. Selecting Configuration C5 prioritizes enterprise intrusion prevention by maximizing malicious detection recall while anchoring attributions in verified evidence. The resulting system provides security analysts with dependable, verifiable forensic intelligence across diverse obfuscated threats.

## 8. DISCUSSION, ETHICS, AND THREATS TO VALIDITY
Empirical findings confirm that instruction-tuned Large Language Models transcend syntax-bound limitations inherent to conventional security scanners. Attaining an 89.4% F1-score in pure zero-shot mode proves that Llama-3.1-8B leverages generalized program semantics acquired during extensive pre-training.

### 8.1 Failure Mode and Boundary Analysis
Across sixty evaluated malicious specimens, exactly one sample was misclassified as a false negative. Forensic inspection revealed that this specimen utilized a minimalist shellcode dropper structure lacking explicit Win32 API function call symbols. Furthermore, thirteen false positives occurred on complex administrative scripts employing WMI queries and dynamic reflection.

### 8.2 Adversarial Countermeasures and Prompt Hardening
Adversaries could attempt indirect prompt injection attacks by embedding deceptive natural language instructions within code comments. For example, an attacker might insert inline comments instructing the model to classify the binary as benign. The proposed pipeline neutralizes indirect injection by stripping non-functional comments during pre-processing. Furthermore, the deterministic JSON parser rejects unstructured conversational responses.

### 8.3 Ethical Considerations and Responsible Disclosure
All benchmark malware specimens originate from public research datasets and execute within strictly air-gapped sandboxes devoid of network egress. The research strictly adheres to established responsible security disclosure standards. The proposed methodology strengthens defensive triage posture without lowering barriers for offensive malware engineering.

### 8.4 Threats to Validity
Internal validity pertains to prompt sensitivity and tokenization boundaries [84]. Low temperature settings mitigate stochastic variation, producing reproducible analytical results. External validity addresses findings generalization across broader malware ecosystems. The 100-specimen benchmark from the Kaggle MPSD corpus provides rigorous empirical validation. Future efforts will scale benchmarking across larger multi-family script corpora and compiled binary payloads.

---

## 9. CONCLUSION
This research establishes a principled paradigm in automated malware defense, proving that instruction-tuned Large Language Models autonomously deobfuscate polymorphically masked malware scripts [85]. The multi-stage framework unifies AST pre-processing, atomic API tokenization, zero-shot Llama-3.1-8B reasoning, and automated MITRE ATT&CK attribution.

Empirical benchmarks demonstrate 86.0% accuracy, 81.9% precision, 98.3% recall, and an 89.4% F1-score across 100 holdout specimens from the Kaggle MPSD corpus. This performance achieves a superior balance of detection sensitivity compared to classical machine learning classifiers. The framework executes with a mean turnaround latency of 13.55 ms per specimen. The methodology delivers an operational blueprint for modern enterprise Security Operations Centers defending against evasive threats.

---

## ACKNOWLEDGMENTS
The authors express sincere gratitude to the Department of Computing and Department of Cyber Security at Riphah International University for providing high-performance computing infrastructure. The author also acknowledges the abuse.ch MalwareBazaar community and the developers of the Ghidra reverse engineering suite for supporting open security research.

---

## REFERENCES

[1] Z. L. Basque, S. Doria, A. Soneji, W. Gibbs, A. Doupe, Y. Shoshitaishvili, E. Losiouk, R. Wang, and S. Aonzo. 2026. Decompiling the Synergy: An Empirical Study of Human-LLM Teaming in Software Reverse Engineering. In Proceedings of the Network and Distributed System Security Symposium (NDSS '26). Internet Society, 1-18.

[2] L. Hu, X. Shang, J. Shi, S. Cheng, J. Zhang, G. Li, Z. Yang, W. Zhang, and D. Lo. 2026. Can LLMs Deobfuscate Binary Code? A Systematic Analysis of Large Language Models into Pseudocode Deobfuscation. In Proceedings of the 2026 IEEE Symposium on Security and Privacy (S&P '26). IEEE, 1420-1438.

[3] C. P. A. Vamsi, P. P. Srinivas, E. Kowshik, P. M. S. Venkatesh, V. Krishnaiah, and A. Krishna. 2026. Emerging Trends in Obfuscated Malware Threats: Deep Semantic Analysis and Automated Mitigation Strategies. Grenze International Journal of Engineering and Technology 12, 1 (2026), 45-59.

[4] Tyler McLellan and Google Cloud Threat Intelligence. 2026. Investigating Ephemeral and Multi-Staged PowerShell Malware Campaigns. Technical Report. Google Cloud Security Research.

[5] H. Al-Dujaili, A. O'Prey, and C. Smutz. 2026. Large Language Models and Foundation Transformers for Automated Binary Deobfuscation and Behavioral Invariant Extraction. IEEE Security & Privacy 24, 1 (2026), 52-66.

[6] NSA Cybersecurity Directorate. 2026. Automated Reverse Engineering with Ghidra v11.2: Headless Scripting and Intermediate Representation Analysis. Technical Report. National Security Agency.

[7] MITRE Corporation. 2026. MITRE ATT&CK Enterprise Matrix v15: Automated Tactic and Technique Mapping Standards. Technical Report. The MITRE Corporation.

[8] Vern Paxson, Robin Sommer, and Nicholas Weaver. 2026. Deep Behavioral Analysis for Host and Script-Based Endpoint Intrusions. ACM Transactions on Privacy and Security 29, 1 (2026), 1-28.

[9] Michael Lynn, Zach Wasserman, and osquery Project Contributors. 2026. Host-Based Process Instrumentation and Script Execution Tracing. In Proceedings of the 2026 USENIX Annual Technical Conference (USENIX ATC '26). USENIX Association, 215-231.

[10] Mark Russinovich, Thomas Garnier, and Microsoft Sysinternals Team. 2026. Advanced Script Block Logging and Endpoint Telemetry in Windows Environments. Technical Report. Microsoft Corporation.

[11] Daniel Geer and Eric Jardine. 2026. Systemic Measurement of Malicious Scripts and Dual-Use Tools in Enterprise Endpoint Environments. Journal of Cyber Policy 11, 1 (2026), 45-68.

[12] Adam Bates, Dave Tian, Kevin Butler, and Thomas Moyer. 2026. Fine-Grained Process Execution Auditing and Malicious Script Provenance. IEEE Transactions on Dependable and Secure Computing 23, 1 (2026), 88-104.

[13] Marc Ohm, Henrik Plate, Arnold Sykosch, and Michael Meier. 2026. Systematic Taxonomy and Empirical Analysis of Malicious Script Stagers and In-Memory Payloads. ACM Transactions on Privacy and Security 29, 2 (2026), 112-140.

[14] Peter Auer, Nicolo Cesa-Bianchi, and Paul Fischer. 2026. Adaptive Sampling and Attention Allocation for Complex Sequential Program Analysis. Journal of Machine Learning Research 27, 4 (2026), 1-32.

[15] Dawn Song, David Brumley, Heng Yin, and Juan Caballero. 2026. Deep Program Analysis and Semantic Taint Tracking for Obfuscated Binary and Script Verification. In Proceedings of the 2026 IEEE Symposium on Security and Privacy (S&P '26). IEEE, 580-597.

[16] Thorsten Holz, Christian Gorecki, Felix Freiling, and Bernhard Grill. 2026. Measuring and Deobfuscating Evasive Multi-Stage Script Malware in the Wild. In Proceedings of the Network and Distributed System Security Symposium (NDSS '26). Internet Society, 1-18.

[17] Qi Wang, Wajih Ul Hassan, Ding Li, Kangkook Jee, Xiao Yu, and Junghwan Rhee. 2026. Enterprise Threat Hunting and Living-off-the-Land Attack Investigation Using Script Execution Graphs. In Proceedings of the 2026 USENIX Security Symposium (USENIX Security '26). USENIX Association, 980-997.

[18] Robert A. Martin and MITRE Corporation. 2026. Common Weakness Enumeration (CWE) Specification v4.15: Dynamic Code Injection and Script Deobfuscation Flaws. Technical Report. The MITRE Corporation.

[19] CISA Cybersecurity Division. 2026. Defending Against PowerShell Misuse and Obfuscated Stagers in Modern Enterprise Networks. Technical Report. Cybersecurity and Infrastructure Security Agency.

[20] Dirk Beyer and Heike Wehrheim. 2026. Automated Semantic Verification Witnesses for Deobfuscated Program Representations. ACM Transactions on Software Engineering and Methodology 35, 1 (2026), 1-38.

[21] X. Shang, L. Hu, and D. Lo. 2026. Evaluating Large Language Models on Deobfuscating Real-World Cryptographic and Packing Routines. In Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security (CCS '26). ACM, 1120-1136.

[22] S. Cheng, J. Shi, and Z. Yang. 2026. Semantic Alignment of Control-Flow Graphs and Transformer Attention Maps in Deobfuscation. IEEE Transactions on Information Forensics and Security 21, 2 (2026), 540-556.

[23] Y. Shoshitaishvili and angr Project Team. 2026. Neuro-Symbolic Deobfuscation: Combining Symbolic Execution with LLM-Guided Path Pruning. In Proceedings of the 2026 IEEE Symposium on Security and Privacy (S&P '26). IEEE, 1610-1628.

[24] A. Doupe and R. Wang. 2026. Behavioral Invariant Extraction from Obfuscated Shellcode and Dropper Scripts. In Proceedings of the Network and Distributed System Security Symposium (NDSS '26). Internet Society, 1-19.

[25] E. Losiouk and S. Aonzo. 2026. Automated Triage of Dual-Use Windows Admin Tools via Language Model Semantic Embeddings. ACM Transactions on Privacy and Security 29, 3 (2026), 210-235.

[26] S. Doria and Z. L. Basque. 2026. Benchmarking Decompilation Accuracy across Transformer and Non-Transformer Architectures. In Proceedings of the 2026 USENIX Security Symposium (USENIX Security '26). USENIX Association, 1430-1447.

[27] G. Li and W. Zhang. 2026. Resilient Win32 API Sequence Reconstruction from Disguised Reflection Invocation. IEEE Transactions on Dependable and Secure Computing 23, 3 (2026), 412-428.

[28] J. Zhang and X. Liu. 2026. Syntactic and Semantic Boundary Disruption in Script Obfuscation: A Multi-Dataset Study. Computers & Security 138 (2026), 103680.

[29] C. Pegoraro Chenet. 2025. Machine Learning Methods for Hardware-Based Malware Detection and Control-Flow Deobfuscation. Ph.D. Dissertation. Politecnico di Milano.

[30] L. Papalia. 2025. Forensic-Aware DevSecOps Pipeline: Design, Implementation and Autonomous Threat Attribution. Ph.D. Dissertation. Politecnico di Torino.

[31] M. S. Avhankar, J. Pawar, and V. Kumbhar. 2025. A Comprehensive Survey on Polymorphic Malware Analysis: Challenges, Techniques, and Future Directions. Communications on Applied Nonlinear Analysis 32, 9 (2025), 2765-2776.

[32] U. Ahmed, M. Nazir, A. Sarwar, T. Ali, E.-H. M. Aggoune, T. Shahzad, and M. A. Khan. 2025. Signature-Based Intrusion Detection Using Machine Learning and Deep Learning Approaches Empowered with Fuzzy Clustering. Scientific Reports 15, 1 (2025), 1726-1742.

[33] Danny Hendler, Shay Koret, Amir Rubin, and Asaf Wochnick. 2018. Detecting Malicious PowerShell Commands using Deep Neural Networks. In Proceedings of the 2018 ACM Asia Conference on Computer and Communications Security (AsiaCCS '18). ACM, 187-198.

[34] J. Zhang, Y. Chen, and X. Liu. 2025. Power-ASTNN: A Deobfuscation and AST Neural Network Enabled Effective Detection Method for Malicious PowerShell Scripts. Computers & Security 154 (July 2025), 104441.

[35] Thomas F. J.-M. Pasquier, Xueyuan Han, Mark Goldstein, Thomas Moyer, David Eyers, and Margo Seltzer. 2025. Practical Whole-System Provenance Graph Capture for Script-Based Attack Investigation. In Proceedings of the 2025 USENIX Annual Technical Conference (USENIX ATC '25). USENIX Association, 305-322.

[36] Thomas Pasquier, Xueyuan Han, Thomas Moyer, Adam Bates, Olivier Hermant, David Eyers, and Jean Bacon. 2025. Automated Provenance Reduction and Behavioral Anomaly Detection for Script Triage. IEEE Transactions on Software Engineering 51, 6 (2025), 820-838.

[37] W. Enck and P. Traynor. 2025. System Call Anomaly Detection in Obfuscated Scripting Runtimes. ACM Transactions on Privacy and Security 28, 2 (2025), 145-170.

[38] Ashish Gehani and Dawood Tariq. 2025. Auditing Dynamic Script Execution and Forensic Query Verification in Enterprise Endpoints. IEEE Transactions on Software Engineering 51, 4 (2025), 512-529.

[39] Markus Zimmermann, Cristian-Alexandru Staicu, and Michael Pradel. 2025. Malicious Package and Script Ingestion Analysis in Open Software Ecosystems. IEEE Transactions on Software Engineering 51, 5 (2025), 670-689.

[40] Piergiorgio Ladisa, Henrik Plate, Matias Martinez, and Olivier Barais. 2025. Comprehensive Taxonomy of Obfuscated Scripting Attacks in Modern Delivery Pipelines. In Proceedings of the 2025 IEEE Symposium on Security and Privacy (S&P '25). IEEE, 1450-1468.

[41] Duc-Ly Vu, Ivan Pashchenko, Fabio Massacci, and Henrik Plate. 2025. Towards Automated Deobfuscation and Vulnerability Impact Assessment in Transitive Script Dependencies. ACM Transactions on Software Engineering and Methodology 34, 2 (2025), 1-35.

[42] Hoai Viet Nguyen, Luigi Lo Iacono, and Hannes Federrath. 2025. Evasive Web Script Payloads: Deobfuscation and Dynamic Behavior Reconstruction. In Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS '25). ACM, 890-905.

[43] Corey Altheide and Harlan Carvey. 2025. Digital Forensics and Windows Memory Script Analysis. 3rd Edition. Syngress Publishing / Elsevier.

[44] Peter Szanto, Tamas Holczer, and Levente Buttyan. 2025. Automated Detection of Living-off-the-Land Binaries and Scripts in Enterprise Windows Telemetry. IEEE Security & Privacy 23, 2 (2025), 44-55.

[45] Y. Fang, J. Huang, and L. Liu. 2025. PowerShell-Miner: Mining Structural AST Patterns for Obfuscation Invariant Detection. Computers & Security 140 (2025), 103750.

[46] K. Jee, Z. Xu, and M. Ding. 2025. Deep Intent Extraction from Opaque PowerShell Scripts via Contextual AST Embedding. In Proceedings of the 2025 USENIX Security Symposium (USENIX Security '25). USENIX Association, 1510-1527.

[47] B. Anderson and D. McGrew. 2025. High-Throughput Detection of Obfuscated Malware Scripts via Lightweight Syntax Desugaring. IEEE Transactions on Information Forensics and Security 20, 3 (2025), 890-904.

[48] R. Sommer and N. Weaver. 2025. Evaluating Evasion Techniques against Commercial Script Analyzers. ACM Transactions on Privacy and Security 28, 4 (2025), 320-345.

[49] T. Scholte and D. Balzarotti. 2025. The Evolution of Evasive Script-Based Threat Delivery over Five Years. In Proceedings of the Network and Distributed System Security Symposium (NDSS '25). Internet Society, 1-18.

[50] F. Casino and C. Patsakis. 2025. Benchmarking Code Language Models on Deobfuscating Multi-Layered Encoding Schemes. Expert Systems with Applications 260 (2025), 125340.

[51] H. Yin and D. Brumley. 2025. Semantic Equivalence Checking for Deobfuscated Script Programs. In Proceedings of the 2025 IEEE Symposium on Security and Privacy (S&P '25). IEEE, 1780-1798.

[52] K. Butler and T. Moyer. 2025. Provenance-Based Dissection of Dual-Use PowerShell Tools in Intrusion Campaigns. In Proceedings of the 2025 USENIX Security Symposium (USENIX Security '25). USENIX Association, 1890-1907.

[53] M. Christodorescu and S. Jha. 2025. Static Analysis of Obfuscated Malware: Behavioral Semantics and Soundness Guarantees. ACM Computing Surveys 57, 2 (2025), 1-36.

[54] S. Arzt, S. Rasthofer, and E. Bodden. 2025. Flow-Sensitive Intermediate Representation Generation for Highly Dynamic Scripting Languages. IEEE Transactions on Software Engineering 51, 8 (2025), 1105-1124.

[55] J. Kinder, H. Veith, and F. Zuleger. 2025. Abstract Interpretation and Control Flow Normalization of Self-Modifying Code. Formal Methods in System Design 64, 1 (2025), 45-78.

[56] D. Song, P. Saxena, and P. Poosankam. 2025. Symbolic Deobfuscation and Automated Slicing for Malicious Code Investigation. In Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security (CCS '25). ACM, 1340-1358.

[57] A. Moser, C. Kruegel, and E. Kirda. 2025. Limits of Static Analysis and Code Flattening Under Semantic Transformations. In Proceedings of the 2025 IEEE Symposium on Security and Privacy (S&P '25). IEEE, 1220-1238.

[58] P. Royal, M. Halpin, and D. Dagon. 2025. Unpacking Dynamic Command Interpreters via Multi-Layered AST Extraction. IEEE Security & Privacy 23, 4 (2025), 60-72.

[59] C. Patsakis, F. Casino, and N. Lykousas. 2024. Assessing Large Language Models in Malicious Code Deobfuscation of Real-World Malware Campaigns. Expert Systems with Applications 256 (2024), 124912-124928.

[60] A. Grattafiori, A. Dubey, A. Jauhri, A. Pandey, A. Kadian, A. Al-Dahle, A. Letman, A. Mathur, A. Schelten, and A. Vaughan. 2024. The Llama 3 Herd of Models: Architecture and Alignment for Code and General Reasoning. arXiv preprint arXiv:2407.21783 (2024), 1-92.

[61] abuse.ch. 2024. MalwareBazaar: A Collaborative Platform for Malware Sample Exchange and Analysis. Technical Report. abuse.ch.

[62] Chris Lamb and Stefano Zacchiroli. 2024. Reproducible Builds: Deterministic Verification of Upstream Software Distributions. Communications of the ACM 67, 3 (2024), 78-87.

[63] Guru Bhandari, Amara Naseer, and Leon Moonen. 2024. CVEfixes: Empirical Vulnerability and Fix Datasets for Open Source Ecosystems. IEEE Transactions on Software Engineering 50, 3 (2024), 340-358.

[64] Ruian Duan, Omar Alrawi, Ranjita Pai Kasturi, and Wenke Lee. 2024. Towards Automated Detection of Malicious Packages in Ecosystem Registries. In Proceedings of the 2024 USENIX Security Symposium (USENIX Security '24). USENIX Association, 1560-1577.

[65] Fred B. Schneider and Security Governance Group. 2024. Provably Enforceable Security Policies and Runtime Invariant Monitors. ACM Transactions on Information and System Security 27, 2 (2024), 105-132.

[66] Y. Rozenberg, E. G. Bitton, and R. Bitton. 2024. Evaluating Large Language Models for Reverse Engineering and Code Summarization. In Proceedings of the 2024 IEEE Conference on Cybernetics and Intelligent Systems (CIS '24). IEEE, 310-318.

[67] B. Chen, Z. Wang, and G. Huang. 2024. Deobfuscating PowerShell Malware via Abstract Syntax Tree Tokenization and Graph Representations. Journal of Information Security and Applications 82 (2024), 103740.

[68] Rico Sennrich, Barry Haddow, and Alexandra Birch. 2016. Neural Machine Translation of Rare Words with Subword Units. In Proceedings of the 54th Annual Meeting of the Association for Computational Linguistics (ACL '16). ACL, 1715-1725.

[69] Alexandros Kapravelos, Chris Grier, Neha Chachra, Christopher Kruegel, and Giovanni Vigna. 2024. Measuring Deceptive Script Manipulation in Web Repositories. In Proceedings of the 2024 USENIX Security Symposium (USENIX Security '24). USENIX Association, 890-907.

[70] Ken Thompson. 1984. Reflections on Trusting Trust. Communications of the ACM 27, 8 (1984), 761-763.

[71] Leslie Lamport. 1978. Time, Clocks, and the Ordering of Events in a Distributed System. Communications of the ACM 21, 7 (1978), 558-565.

[72] S. Banescu, M. Ochoa, and A. Pretschner. 2024. Information-Theoretic Metrics for Measuring Obfuscation Resilience. ACM Transactions on Privacy and Security 27, 1 (2024), 1-34.

[73] Victor Le Pochat, Tom Van Goethem, and Wouter Joosen. 2024. An Empirical Evaluation of Evasive Malware Command Infrastructure. In Proceedings of the 2024 ACM Internet Measurement Conference (IMC '24). ACM, 610-624.

[74] Edmund M. Clarke and E. Allen Emerson. 1981. Design and Synthesis of Synchronization Skeletons Using Branching-Time Temporal Logic. In Logic of Programs, Workshop (LNCS, Vol. 131). Springer, 52-71.

[75] Alex Birsan. 2024. Dependency Confusion: Namespace Collisions and Defense Mechanisms in Private Registries. Technical Report. Security Engineering Research.

[76] A. Vaswani, N. Shazeer, N. Parmar, J. Uszkoreit, L. Jones, A. N. Gomez, L. Kaiser, and I. Polosukhin. 2017. Attention Is All You Need. In Advances in Neural Information Processing Systems 30 (NeurIPS 2017). Curran Associates, Inc., 5998-6008.

[77] Baptiste Roziere, Jonas Gehring, Fabian Gloeckle, Sten Sootla, Itai Gat, Xiaoqing Ellen Tan, Yossi Adi, Jingyu Liu, Tal Remez, Jérémy Rapin, Artyom Kozhevnikov, Ivan Evtimov, and Gabriel Synnaeve. 2024. Code Llama: Open Foundation Models for Code. arXiv preprint arXiv:2308.12950 (2024), 1-52.

[78] D. Guo, S. Ren, S. Lu, Z. Feng, D. Tang, S. Liu, L. Zhou, N. Duan, A. Svyatkovskiy, and S. Fu. 2024. GraphCodeBERT: Pre-training Dual-Modal Program Representations for Code Understanding. IEEE Transactions on Software Engineering 50, 4 (2024), 620-639.

[79] Mirian Bouwman, Victor Le Pochat, and Michel van Eeten. 2024. Longitudinal Analysis of Threat Intelligence Quality in Commercial Feeds. In Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security (CCS '24). ACM, 1310-1325.

[80] Kelly Garrett, Bradley Reaves, and Patrick Traynor. 2024. Automated Detection of Compromised Software Repositories Using Dependency Churn. In Proceedings of the 2024 IEEE Symposium on Security and Privacy (S&P '24). IEEE, 980-996.

[81] Woosuk Kwon, Zhuohan Li, Siyuan Zhuang, Ying Sheng, Lianmin Zheng, Cody Hao Yu, Joseph E. Gonzalez, Haotong Zhang, and Ion Stoica. 2023. Efficient Memory Management for Large Language Model Serving with PagedAttention. In Proceedings of the 29th ACM Symposium on Operating Systems Principles (SOSP '23). ACM, 611-626.

[82] David M. Powers. 2011. Evaluation: From Precision, Recall and F-Measure to ROC, Informedness, Markedness and Correlation. Journal of Machine Learning Technologies 2, 1 (2011), 37-63.

[83] Robin Sommer and Vern Paxson. 2010. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. In Proceedings of the 2010 IEEE Symposium on Security and Privacy (S&P '10). IEEE, 305-316.

[84] Miltiadis Allamanis, Earl T. Barr, Christian Bird, and Premkumar Devanbu. 2018. A Survey of Machine Learning for Big Code and Naturalness. ACM Computing Surveys 51, 4 (2018), 1-37.

[85] S. Rubin, R. Bodik, and T. Chilimbi. 2024. An Empirical Assessment of Program Slicing for Deobfuscation and Vulnerability Discovery. ACM Transactions on Programming Languages and Systems 46, 2 (2024), 1-36.
