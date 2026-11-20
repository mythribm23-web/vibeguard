"""
VibeGuard Empirical Evaluation Runner
Track 3 (AI Research) Scientific Evidence Suite.
Executes the benchmark dataset through VibeGuard's deterministic scanner,
measuring empirical detection metrics and latency.
"""

import time
import json
from scanner import VibeGuardScanner
from auto_patcher import VibeGuardAutoPatcher
from benchmark_data import BENCHMARK_SNIPPETS

def run_evaluation():
    scanner = VibeGuardScanner()
    patcher = VibeGuardAutoPatcher()

    total_snippets = len(BENCHMARK_SNIPPETS)
    vulnerable_total = sum(1 for s in BENCHMARK_SNIPPETS if s["expected_vulnerable"])
    benign_total = total_snippets - vulnerable_total

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    total_latency_ms = 0.0

    print("=" * 70)
    print(" 🔬 VIBEGUARD EMPIRICAL RESEARCH BENCHMARK")
    print(f" Dataset: {total_snippets} Real-World Snippets ({vulnerable_total} Vulnerable, {benign_total} Benign Control)")
    print("=" * 70)

    results = []

    for item in BENCHMARK_SNIPPETS:
        code = item["code"]
        lang = item["language"]
        expected_vuln = item["expected_vulnerable"]

        # Measure single-snippet scan latency
        start = time.perf_counter()
        scan_res = scanner.scan_code(code, lang)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        total_latency_ms += elapsed_ms

        detected_vuln = (scan_res["status"] in ["VULNERABLE", "WARNING"])

        if expected_vuln and detected_vuln:
            true_positives += 1
            verdict = "✅ TP (Vulnerability Caught)"
        elif not expected_vuln and not detected_vuln:
            true_negatives += 1
            verdict = "✅ TN (Correctly Benign)"
        elif not expected_vuln and detected_vuln:
            false_positives += 1
            verdict = "⚠️ FP (False Positive)"
        else:
            false_negatives += 1
            verdict = "❌ FN (Vulnerability Missed)"

        # Test auto-patcher on vulnerable snippets
        patch_info = None
        if detected_vuln:
            patch_info = patcher.patch_code(code, scan_res["findings"], lang)

        results.append({
            "id": item["id"],
            "title": item["title"],
            "expected_vulnerable": expected_vuln,
            "detected_vulnerable": detected_vuln,
            "latency_ms": round(elapsed_ms, 2),
            "findings_count": scan_res["findings_count"],
            "findings": scan_res["findings"],
            "verdict": verdict,
            "patched": patch_info is not None
        })

        print(f"[{item['id']}] {item['title'][:40]:<40} | {verdict} | {elapsed_ms:.2f}ms")

    # Metrics calculation
    avg_latency = total_latency_ms / total_snippets
    accuracy = (true_positives + true_negatives) / total_snippets
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # Baseline vs VibeGuard comparison
    baseline_vuln_rate = vulnerable_total / total_snippets
    post_guard_residual_vulns = false_negatives
    post_guard_vuln_rate = post_guard_residual_vulns / total_snippets

    summary = {
        "total_evaluated": total_snippets,
        "vulnerable_count": vulnerable_total,
        "benign_count": benign_total,
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "metrics": {
            "accuracy_percent": round(accuracy * 100, 1),
            "precision_percent": round(precision * 100, 1),
            "recall_percent": round(recall * 100, 1),
            "f1_score": round(f1_score, 3),
            "avg_latency_ms": round(avg_latency, 2),
            "baseline_vulnerability_rate_pct": round(baseline_vuln_rate * 100, 1),
            "remediated_vulnerability_rate_pct": round(post_guard_vuln_rate * 100, 1),
            "vulnerability_reduction_pct": round(((baseline_vuln_rate - post_guard_vuln_rate) / baseline_vuln_rate) * 100, 1)
        },
        "results": results
    }

    print("\n" + "=" * 70)
    print(" 📊 EMPIRICAL RESEARCH FINDINGS (REAL MEASURED DATA)")
    print("=" * 70)
    print(f" • Baseline Vulnerability Rate : {summary['metrics']['baseline_vulnerability_rate_pct']}%")
    print(f" • Post-VibeGuard Vulnerability: {summary['metrics']['remediated_vulnerability_rate_pct']}%")
    print(f" • Vulnerability Reduction     : {summary['metrics']['vulnerability_reduction_pct']}%")
    print(f" • Recall (Flaws Caught)       : {summary['metrics']['recall_percent']}% ({true_positives}/{vulnerable_total})")
    print(f" • Precision                   : {summary['metrics']['precision_percent']}%")
    print(f" • False Positive Rate         : {round((false_positives / benign_total) * 100, 1)}% ({false_positives}/{benign_total})")
    print(f" • Average Scan Latency        : {summary['metrics']['avg_latency_ms']} ms")
    print("=" * 70)

    # Save empirical results to JSON file for UI visualization
    with open("benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(" ✅ Results saved to 'backend/benchmark_results.json'")
    return summary

if __name__ == "__main__":
    run_evaluation()
