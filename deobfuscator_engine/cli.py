"""
deobfuscator_engine.cli
~~~~~~~~~~~~~~~~~~~~~~~
Command-Line Interface for Transformer-Based Semantic Deobfuscation Prototype.
Enables batch evaluation, single-file forensic deobfuscation, and benchmarking.
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path
from .dossier_generator import DossierGenerator

def main():
    parser = argparse.ArgumentParser(
        description="Transformer-Based Semantic Deobfuscation Engine (ACM TOPS Prototype)"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        default=None,
        help="Path to obfuscated script (.ps1, .bat), directory, or compiled binary (.exe, .dll)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="./forensic_dossiers",
        help="Directory to save generated JSON forensic dossiers"
    )
    parser.add_argument(
        "--model", "-m",
        type=str,
        default="Llama-3.1-8B-Instruct",
        help="Underlying transformer foundation model identifier"
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run latency, token efficiency, and classification benchmarking on benchmark dataset"
    )

    args = parser.parse_args()

    if not args.input and not args.benchmark:
        parser.print_help()
        sys.exit(0)

    generator = DossierGenerator(model_name=args.model)

    if args.benchmark and not args.input:
        # Locate packaged benchmark dataset
        bench_paths = [
            Path(__file__).resolve().parent.parent / "data" / "processed" / "benchmark_test_samples.json",
            Path("data/processed/benchmark_test_samples.json"),
            Path("../data/processed/benchmark_test_samples.json")
        ]
        benchmark_file = next((p for p in bench_paths if p.exists()), None)
        if not benchmark_file:
            print("[-] Error: benchmark_test_samples.json not found.", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Running Automated Benchmark Suite using: {benchmark_file}")
        with open(benchmark_file, "r", encoding="utf-8") as f:
            bench_samples = json.load(f)

        total_samples = len(bench_samples)
        tp = fp = tn = fn = 0
        latencies = []

        print(f"[*] Executing pipeline across {total_samples} benchmark samples...")
        for idx, item in enumerate(bench_samples):
            code = item["code"]
            is_gt_mal = (item.get("ground_truth_label") == "MALICIOUS" or item.get("is_malicious", False))
            
            t0 = time.perf_counter()
            dossier = generator.generate_from_code(code, filename=item.get("sample_id", f"sample_{idx}.ps1"))
            lat_ms = (time.perf_counter() - t0) * 1000
            latencies.append(lat_ms)

            pred_mal = (dossier["forensic_assessment"]["verdict"] == "MALICIOUS")
            if pred_mal and is_gt_mal:
                tp += 1
            elif pred_mal and not is_gt_mal:
                fp += 1
            elif not pred_mal and not is_gt_mal:
                tn += 1
            else:
                fn += 1

        acc = (tp + tn) / total_samples if total_samples else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

        print("\n" + "=" * 50)
        print("           ACM TOPS BENCHMARK SUMMARY")
        print("=" * 50)
        print(f"Total Evaluated Samples : {total_samples}")
        print(f"Confusion Matrix        : TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        print(f"Accuracy                : {acc * 100:.2f}%")
        print(f"Precision               : {prec * 100:.2f}%")
        print(f"Recall (Detection Rate) : {rec * 100:.2f}%")
        print(f"F1-Score                : {f1 * 100:.2f}%")
        print(f"Mean Pipeline Latency   : {avg_lat:.2f} ms")
        print("=" * 50)
        sys.exit(0)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] Error: Input path does not exist: {args.input}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    generator = DossierGenerator(model_name=args.model)

    if input_path.is_file():
        files_to_process = [input_path]
    else:
        files_to_process = list(input_path.glob("*.ps1")) + list(input_path.glob("*.exe"))

    print(f"[*] Processing {len(files_to_process)} target artifact(s)...")

    results = []
    for f in files_to_process:
        print(f"[*] Deobfuscating: {f.name}")
        t0 = time.perf_counter()
        dossier = generator.generate_from_file(str(f))
        elapsed = time.perf_counter() - t0

        out_name = f"{dossier['artifact_metadata']['sha256'][:16]}_dossier.json"
        out_file = os.path.join(args.output_dir, out_name)
        generator.save_dossier_json(dossier, out_file)

        verdict = dossier["forensic_assessment"]["verdict"]
        conf = dossier["forensic_assessment"]["confidence_score"]
        ttps = dossier["mitre_attack_attribution"]["technique_count"]
        corrob_apis = len(dossier["forensic_assessment"]["corroborated_apis"])

        print(f"    Verdict: {verdict} (Confidence: {conf:.2f})")
        print(f"    Corroborated APIs: {corrob_apis} | Mapped MITRE TTPs: {ttps}")
        print(f"    Latency: {elapsed*1000:.1f} ms -> Saved: {out_file}")

        results.append(dossier)

    if args.benchmark and results:
        avg_lat = sum(r["pipeline_latencies"]["total_wall_clock_sec"] for r in results) / len(results)
        print("\n=== BENCHMARK SUMMARY ===")
        print(f"Total Samples Analyzed: {len(results)}")
        print(f"Mean Wall-Clock Latency: {avg_lat*1000:.2f} ms")
        print("=========================")

if __name__ == "__main__":
    main()

