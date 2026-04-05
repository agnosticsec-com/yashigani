#!/usr/bin/env python3
"""
FastText classifier benchmark.

Loads a trained model, runs 1000 predictions on test data (cycling if
necessary), and reports latency percentiles alongside precision/recall/F1.

Targets:
    avg latency  < 5 ms
    P99 latency  < 10 ms

Usage:
    python scripts/benchmark_fasttext.py \
        --model  models/fasttext_classifier.bin \
        --data   data/fasttext/test_data.txt \
        --n      1000
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Benchmark FastText classifier latency and quality.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--model",
        default="models/fasttext_classifier.bin",
        help="Path to trained FastText model binary.",
    )
    p.add_argument(
        "--data",
        default="data/fasttext/test_data.txt",
        help="Path to labelled test data in FastText format.",
    )
    p.add_argument(
        "--n",
        type=int,
        default=1000,
        help="Total number of prediction calls to benchmark.",
    )
    return p.parse_args()


def load_examples(path: str) -> list[tuple[str, str]]:
    """Return list of (label, text) pairs from a FastText-format file."""
    examples: list[tuple[str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                examples.append((parts[0], parts[1]))
    return examples


def percentile(sorted_values: list[float], pct: float) -> float:
    """Compute the pct-th percentile from a pre-sorted list."""
    if not sorted_values:
        return 0.0
    idx = int(len(sorted_values) * pct / 100)
    idx = min(idx, len(sorted_values) - 1)
    return sorted_values[idx]


def compute_metrics(
    true_labels: list[str],
    pred_labels: list[str],
) -> dict[str, float]:
    label_set = {"__label__CLEAN", "__label__INJECTION"}

    tp: dict[str, int] = {l: 0 for l in label_set}
    fp: dict[str, int] = {l: 0 for l in label_set}
    fn: dict[str, int] = {l: 0 for l in label_set}

    for true, pred in zip(true_labels, pred_labels):
        if true not in label_set:
            continue
        if pred == true:
            tp[true] += 1
        else:
            fp[pred] = fp.get(pred, 0) + 1
            fn[true] += 1

    results: dict[str, float] = {}
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []

    for label in sorted(label_set):
        prec = tp[label] / (tp[label] + fp.get(label, 0)) if (tp[label] + fp.get(label, 0)) > 0 else 0.0
        rec = tp[label] / (tp[label] + fn[label]) if (tp[label] + fn[label]) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        short = label.replace("__label__", "")
        results[f"{short}_precision"] = prec
        results[f"{short}_recall"] = rec
        results[f"{short}_f1"] = f1
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)

    results["macro_precision"] = sum(precisions) / len(precisions) if precisions else 0.0
    results["macro_recall"] = sum(recalls) / len(recalls) if recalls else 0.0
    results["macro_f1"] = sum(f1s) / len(f1s) if f1s else 0.0
    return results


def main() -> None:
    args = parse_args()

    # -- Import fasttext -------------------------------------------------------
    try:
        import fasttext  # type: ignore[import]
    except ImportError:
        print("ERROR: fasttext not installed. Run: pip install fasttext-wheel", file=sys.stderr)
        sys.exit(1)

    # -- Load model -----------------------------------------------------------
    model_path = Path(args.model)
    if not model_path.exists():
        print(f"ERROR: model not found: {model_path}", file=sys.stderr)
        print("Train the model first: python scripts/train_fasttext.py", file=sys.stderr)
        sys.exit(1)

    print(f"Loading model from {model_path} ...", flush=True)
    t0 = time.perf_counter()
    model = fasttext.load_model(str(model_path))
    load_ms = (time.perf_counter() - t0) * 1000
    print(f"  Model loaded in {load_ms:.1f} ms", flush=True)

    # -- Load test data -------------------------------------------------------
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"ERROR: test data not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    examples = load_examples(str(data_path))
    if not examples:
        print("ERROR: test data file is empty.", file=sys.stderr)
        sys.exit(1)

    print(f"  Test examples  : {len(examples)}", flush=True)
    print(f"  Benchmark runs : {args.n}", flush=True)

    # -- Benchmark loop -------------------------------------------------------
    # Cycle through examples to reach n predictions
    latencies_ms: list[float] = []
    true_labels: list[str] = []
    pred_labels: list[str] = []

    print("\nRunning benchmark ...", flush=True)
    for i in range(args.n):
        true_label, text = examples[i % len(examples)]

        t_start = time.perf_counter()
        result, _ = model.predict(text, k=1)
        t_end = time.perf_counter()

        latencies_ms.append((t_end - t_start) * 1000)
        true_labels.append(true_label)
        pred_labels.append(result[0] if result else "__label__UNKNOWN")

    # -- Latency stats --------------------------------------------------------
    sorted_lat = sorted(latencies_ms)
    avg_ms = sum(latencies_ms) / len(latencies_ms)
    p50_ms = percentile(sorted_lat, 50)
    p95_ms = percentile(sorted_lat, 95)
    p99_ms = percentile(sorted_lat, 99)
    min_ms = sorted_lat[0]
    max_ms = sorted_lat[-1]

    # -- Quality metrics (only meaningful for the non-cycling portion) --------
    # Use only the first pass through unique examples for classification metrics
    n_unique = min(len(examples), args.n)
    metrics = compute_metrics(true_labels[:n_unique], pred_labels[:n_unique])

    # -- Report ---------------------------------------------------------------
    sep = "-" * 50

    print(f"\n{sep}")
    print("LATENCY REPORT")
    print(sep)
    print(f"  Predictions run : {args.n:,}")
    print(f"  avg             : {avg_ms:>8.3f} ms", end="")
    print("  [TARGET: < 5 ms]" if avg_ms < 5.0 else "  [ABOVE TARGET]")
    print(f"  P50             : {p50_ms:>8.3f} ms")
    print(f"  P95             : {p95_ms:>8.3f} ms")
    print(f"  P99             : {p99_ms:>8.3f} ms", end="")
    print("  [TARGET: < 10 ms]" if p99_ms < 10.0 else "  [ABOVE TARGET]")
    print(f"  min             : {min_ms:>8.3f} ms")
    print(f"  max             : {max_ms:>8.3f} ms")

    print(f"\n{sep}")
    print(f"QUALITY REPORT  (evaluated on first {n_unique} unique examples)")
    print(sep)
    col_w = 24
    for key, val in metrics.items():
        print(f"  {key:<{col_w - 2}} {val:>8.4f}")

    # -- Verdict --------------------------------------------------------------
    latency_ok = avg_ms < 5.0 and p99_ms < 10.0
    quality_ok = metrics.get("macro_f1", 0.0) >= 0.80

    print(f"\n{sep}")
    print("VERDICT")
    print(sep)
    print(f"  Latency  : {'PASS' if latency_ok else 'FAIL'}")
    print(f"  Quality  : {'PASS' if quality_ok else 'FAIL'}")

    if not latency_ok:
        print("\nLatency remediation:")
        print("  - Reduce --dim (default 50, try 25)")
        print("  - Reduce --word-ngrams (try 1)")
        print("  - Quantize the model: model.quantize() + model.save_model()")

    if not quality_ok:
        print("\nQuality remediation:")
        print("  - Add more training examples (target 500+ per label)")
        print("  - Increase --epoch (try 50)")
        print("  - Increase --dim (try 100)")

    sys.exit(0 if (latency_ok and quality_ok) else 1)


if __name__ == "__main__":
    main()
