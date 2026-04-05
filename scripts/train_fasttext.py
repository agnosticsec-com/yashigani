#!/usr/bin/env python3
"""
FastText binary classifier trainer — CLEAN vs INJECTION.

Reads a labelled dataset in FastText supervised format:
    __label__CLEAN   <text>
    __label__INJECTION <text>

Performs an 80/20 train/test split, trains a supervised FastText model,
and prints precision, recall, and F1 on the held-out test set.

Usage:
    python scripts/train_fasttext.py \
        --data data/fasttext/training_data.txt \
        --output models/fasttext_classifier.bin

Tuning flags:
    --epoch       Training epochs (default 25)
    --lr          Learning rate (default 0.5)
    --word-ngrams N-gram size (default 2)
    --dim         Embedding dimensions (default 50, keeps model small for <5ms inference)
"""
from __future__ import annotations

import argparse
import math
import os
import random
import sys
import tempfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train a FastText binary classifier (CLEAN vs INJECTION).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--data",
        default="data/fasttext/training_data.txt",
        help="Path to labelled training data in FastText format.",
    )
    p.add_argument(
        "--output",
        default="models/fasttext_classifier.bin",
        help="Path to write the trained model binary.",
    )
    p.add_argument(
        "--epoch",
        type=int,
        default=25,
        help="Number of training epochs.",
    )
    p.add_argument(
        "--lr",
        type=float,
        default=0.5,
        help="Learning rate.",
    )
    p.add_argument(
        "--word-ngrams",
        type=int,
        default=2,
        dest="word_ngrams",
        help="Maximum n-gram size for subword features.",
    )
    p.add_argument(
        "--dim",
        type=int,
        default=50,
        help="Embedding dimension. Use 50 for <5ms inference; increase for higher accuracy.",
    )
    p.add_argument(
        "--min-count",
        type=int,
        default=1,
        dest="min_count",
        help="Minimum token frequency threshold.",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for the train/test split.",
    )
    p.add_argument(
        "--test-split",
        type=float,
        default=0.2,
        dest="test_split",
        help="Fraction of data held out for evaluation.",
    )
    return p.parse_args()


def load_lines(path: str) -> list[str]:
    """Load non-empty lines from a file, stripping trailing whitespace."""
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip() for line in fh if line.strip()]


def split_data(
    lines: list[str],
    test_fraction: float,
    seed: int,
) -> tuple[list[str], list[str]]:
    """Stratified 80/20 split preserving label balance."""
    rng = random.Random(seed)

    by_label: dict[str, list[str]] = {}
    for line in lines:
        label = line.split()[0] if line.split() else "__label__UNKNOWN"
        by_label.setdefault(label, []).append(line)

    train: list[str] = []
    test: list[str] = []

    for label, samples in by_label.items():
        shuffled = samples[:]
        rng.shuffle(shuffled)
        n_test = max(1, math.floor(len(shuffled) * test_fraction))
        test.extend(shuffled[:n_test])
        train.extend(shuffled[n_test:])

    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def write_temp_file(lines: list[str], suffix: str = ".txt") -> str:
    """Write lines to a named temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="yashigani_fasttext_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    return path


def compute_metrics(
    model,
    test_lines: list[str],
) -> dict[str, float]:
    """
    Compute per-label and macro-averaged precision, recall, F1.

    FastText model.predict returns (labels_tuple, probs_tuple).
    """
    label_set = {"__label__CLEAN", "__label__INJECTION"}

    tp: dict[str, int] = {l: 0 for l in label_set}
    fp: dict[str, int] = {l: 0 for l in label_set}
    fn: dict[str, int] = {l: 0 for l in label_set}

    for line in test_lines:
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        true_label, text = parts[0], parts[1]
        if true_label not in label_set:
            continue

        pred_labels, _ = model.predict(text, k=1)
        pred_label = pred_labels[0] if pred_labels else "__label__UNKNOWN"

        if pred_label == true_label:
            tp[true_label] += 1
        else:
            fp[pred_label] = fp.get(pred_label, 0) + 1
            fn[true_label] += 1

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

    # -- Validate input -------------------------------------------------------
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"ERROR: training data not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # -- Import fasttext (must be installed as fasttext-wheel) ----------------
    try:
        import fasttext  # type: ignore[import]
    except ImportError:
        print(
            "ERROR: fasttext not installed. Run: pip install fasttext-wheel",
            file=sys.stderr,
        )
        sys.exit(1)

    # -- Load and split data --------------------------------------------------
    print(f"Loading data from {data_path} ...", flush=True)
    lines = load_lines(str(data_path))
    if not lines:
        print("ERROR: training data file is empty.", file=sys.stderr)
        sys.exit(1)

    train_lines, test_lines = split_data(lines, args.test_split, args.seed)

    label_counts: dict[str, int] = {}
    for line in lines:
        lbl = line.split()[0] if line.split() else "?"
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    print(f"  Total examples : {len(lines)}", flush=True)
    for lbl, cnt in sorted(label_counts.items()):
        print(f"    {lbl}: {cnt}", flush=True)
    print(f"  Train : {len(train_lines)}  |  Test : {len(test_lines)}", flush=True)

    # -- Write temp training file (fasttext requires a file path) -------------
    train_tmp = write_temp_file(train_lines)

    # -- Train ----------------------------------------------------------------
    print(
        f"\nTraining FastText (epoch={args.epoch}, lr={args.lr}, "
        f"wordNgrams={args.word_ngrams}, dim={args.dim}) ...",
        flush=True,
    )
    try:
        # Suppress fasttext's own stdout progress by redirecting internally.
        # fasttext-wheel prints to stdout; we keep it for visibility.
        model = fasttext.train_supervised(
            input=train_tmp,
            epoch=args.epoch,
            lr=args.lr,
            wordNgrams=args.word_ngrams,
            dim=args.dim,
            minCount=args.min_count,
            loss="softmax",
            verbose=0,
        )
    finally:
        os.unlink(train_tmp)

    # -- Save model (strip the .bin suffix; fasttext adds it automatically) ---
    # fasttext.save_model writes exactly the path given — no automatic suffix.
    model.save_model(str(output_path))
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"\nModel saved to {output_path}  ({size_mb:.1f} MB)", flush=True)

    # -- Evaluate on held-out test set ----------------------------------------
    if not test_lines:
        print("WARNING: no test examples available for evaluation.", file=sys.stderr)
        return

    print(f"\nEvaluating on {len(test_lines)} held-out examples ...", flush=True)
    metrics = compute_metrics(model, test_lines)

    col_w = 22
    print("\n" + "-" * 55)
    print(f"{'Metric':<{col_w}} {'Value':>10}")
    print("-" * 55)
    for key, val in metrics.items():
        print(f"  {key:<{col_w - 2}} {val:>10.4f}")
    print("-" * 55)

    macro_f1 = metrics.get("macro_f1", 0.0)
    if macro_f1 >= 0.90:
        verdict = "PASS — model meets quality threshold (F1 >= 0.90)"
    elif macro_f1 >= 0.80:
        verdict = "WARN — model acceptable but below target (F1 >= 0.90)"
    else:
        verdict = "FAIL — model below minimum acceptable quality (F1 < 0.80)"
    print(f"\n{verdict}")

    # Non-zero exit if quality is clearly unacceptable (fails Docker build fast)
    if macro_f1 < 0.70:
        print(
            "ERROR: macro F1 below 0.70. Review training data quality.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
