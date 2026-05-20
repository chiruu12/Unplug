"""CLI runner for dataset evaluation.

Usage:
    uv run python -m benchmarks.run <dataset_path> [--threshold 0.5] [--format json]
    uv run python -m benchmarks.run data/neuralchemy.parquet
    uv run python -m benchmarks.run data/attacks.jsonl --threshold 0.3 --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.evaluate import evaluate, print_report
from benchmarks.loader import load_auto


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Unplug scanners against a dataset")
    parser.add_argument("dataset", type=Path, help="Path to dataset (JSONL, CSV, or Parquet)")
    parser.add_argument(
        "--threshold", type=float, default=0.5, help="Risk score threshold (default: 0.5)"
    )
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--text-col", default="text", help="Column name for text")
    parser.add_argument("--label-col", default="label", help="Column name for label")
    parser.add_argument("--category-col", default="category", help="Column name for category")
    parser.add_argument("--limit", type=int, default=None, help="Max samples to evaluate")

    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"Error: dataset not found: {args.dataset}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {args.dataset}...", file=sys.stderr)
    samples = load_auto(
        args.dataset,
        text_col=args.text_col,
        label_col=args.label_col,
        category_col=args.category_col,
    )

    if args.limit:
        samples = samples[: args.limit]

    print(f"Evaluating {len(samples)} samples (threshold={args.threshold})...", file=sys.stderr)
    result = evaluate(samples, threshold=args.threshold)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
