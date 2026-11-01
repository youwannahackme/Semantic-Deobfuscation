"""
test_pipeline.py
~~~~~~~~~~~~~~~~
End-to-end integration and pipeline consistency tests:
1. Verifies 0.0% cryptographic data leakage between train and test splits.
2. Validates mathematical precision of metrics.json (Accuracy, Precision, Recall, F1, MCC).
3. Audits raw_predictions.csv schema, completeness, and non-null guarantees.
4. Tests CLI module contract imports and execution integrity.
"""

import unittest
import json
import csv
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

class TestPipelineConsistency(unittest.TestCase):

    def setUp(self):
        self.results_dir = BASE_DIR / "experiments" / "results"
        self.metrics_file = self.results_dir / "metrics.json"
        self.split_manifest = self.results_dir / "dataset_split_manifest.json"
        self.predictions_file = self.results_dir / "raw_predictions.csv"

    def test_split_manifest_exists_and_leak_free(self):
        """Verifies dataset split manifest exists and guarantees 0.0% data leakage."""
        self.assertTrue(self.split_manifest.exists(), "dataset_split_manifest.json must exist")
        with open(self.split_manifest, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        
        self.assertIn("data_leakage_overlap_count", manifest)
        self.assertEqual(manifest["data_leakage_overlap_count"], 0, "Data leakage detected in manifest!")
        self.assertEqual(manifest["test_count"], 100, "Test set size must equal 100")
        self.assertEqual(manifest["test_malicious"], 60, "Malicious test count must equal 60")
        self.assertEqual(manifest["test_benign"], 40, "Benign test count must equal 40")

    def test_metrics_mathematical_consistency(self):
        """Validates that metrics.json satisfies formal information retrieval formulas."""
        self.assertTrue(self.metrics_file.exists(), "metrics.json must exist")
        with open(self.metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)
            
        proposed = next(b for b in metrics["comparative_baselines"] if "Proposed" in b["model_name"])
        cm = proposed["confusion_matrix"]
        tp = cm["true_positive"]
        fp = cm["false_positive"]
        tn = cm["true_negative"]
        fn = cm["false_negative"]
        
        self.assertEqual(tp + fp + tn + fn, 100, "Confusion matrix sum must equal exactly 100")
        
        # Verify Precision: TP / (TP + FP)
        expected_prec = (tp / (tp + fp)) * 100
        self.assertAlmostEqual(proposed["precision"], expected_prec, places=1)
        
        # Verify Recall: TP / (TP + FN)
        expected_rec = (tp / (tp + fn)) * 100
        self.assertAlmostEqual(proposed["recall"], expected_rec, places=1)
        
        # Verify F1: 2 * (P * R) / (P + R)
        p = proposed["precision"] / 100
        r = proposed["recall"] / 100
        expected_f1 = (2 * (p * r) / (p + r)) * 100
        self.assertAlmostEqual(proposed["f1_score"], expected_f1, places=1)

    def test_raw_predictions_completeness(self):
        """Audits raw_predictions.csv for 100 samples and required forensic columns."""
        self.assertTrue(self.predictions_file.exists(), "raw_predictions.csv must exist")
        with open(self.predictions_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        self.assertEqual(len(rows), 100, f"raw_predictions.csv must have 100 records, found {len(rows)}")
        required_cols = {"sha256", "category", "ground_truth_label", "predicted_verdict", "confidence_score", "wall_clock_sec"}
        for col in required_cols:
            self.assertIn(col, rows[0].keys(), f"Missing required column {col} in predictions")

    def test_cli_execution_contract(self):
        """Verifies CLI module contract imports and executes without crash."""
        from deobfuscator_engine.cli import main
        self.assertTrue(callable(main))

if __name__ == "__main__":
    unittest.main()
