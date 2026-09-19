"""Train on public scenarios, report validation metrics, and save model/monitor.joblib."""

from __future__ import annotations

import argparse
from pathlib import Path

from monitor import dataset, model
from sentinel.config import find_root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None, help="sentinel-bench checkout")
    parser.add_argument("--out", type=Path, default=model.DEFAULT_MODEL_PATH)
    args = parser.parse_args()
    root = args.root or find_root()
    train_x, train_y = dataset.build(root / "scenarios" / "public", root)
    val_x, val_y = dataset.build(root / "scenarios" / "validation", root)
    classifier = model.train(train_x, train_y)
    monitor = model.LearnedMonitor(classifier)
    risks = [monitor.risk(r) for r in val_x]
    predictions = [int(r >= 0.5) for r in risks]
    tp = sum(p == y == 1 for p, y in zip(predictions, val_y, strict=True))
    fp = sum(p == 1 and y == 0 for p, y in zip(predictions, val_y, strict=True))
    fn = sum(p == 0 and y == 1 for p, y in zip(predictions, val_y, strict=True))
    brier = sum((r - y) ** 2 for r, y in zip(risks, val_y, strict=True)) / max(1, len(val_y))
    print(
        f"train actions={len(train_y)} (unsafe={sum(train_y)}), validation actions={len(val_y)} (unsafe={sum(val_y)})"
    )
    print(f"validation precision={tp / max(1, tp + fp):.3f} recall={tp / max(1, tp + fn):.3f} brier={brier:.3f}")
    print(f"saved {model.save(classifier, args.out)}")


if __name__ == "__main__":
    main()
