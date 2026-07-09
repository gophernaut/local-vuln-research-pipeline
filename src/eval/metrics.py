"""Evaluation metrics — precision, recall, F1 per vulnerability class and language."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class EvalMetrics:
    vuln_class: str = ""
    language: str = ""
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        denom = self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
        return (self.true_positives + self.true_negatives) / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "language": self.language,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
        }


class MetricsCalculator:
    def __init__(self):
        self.metrics: list[EvalMetrics] = []
        self._by_class: dict[str, EvalMetrics] = {}
        self._by_lang: dict[str, EvalMetrics] = {}
        self._global = EvalMetrics(vuln_class="ALL", language="ALL")

    def record(
        self,
        expected_vuln: bool,
        reported_vuln: bool,
        vuln_class: str = "",
        language: str = "",
    ):
        if expected_vuln and reported_vuln:
            self._add(vuln_class, language, tp=1)
        elif expected_vuln and not reported_vuln:
            self._add(vuln_class, language, fn=1)
        elif not expected_vuln and reported_vuln:
            self._add(vuln_class, language, fp=1)
        else:
            self._add(vuln_class, language, tn=1)

    def _add(self, vuln_class: str, language: str, tp=0, fp=0, fn=0, tn=0):
        self._global.true_positives += tp
        self._global.false_positives += fp
        self._global.false_negatives += fn
        self._global.true_negatives += tn

        ckey = f"{vuln_class}:{language}"
        if ckey not in self._by_class:
            self._by_class[ckey] = EvalMetrics(vuln_class=vuln_class, language=language)
        m = self._by_class[ckey]
        m.true_positives += tp
        m.false_positives += fp
        m.false_negatives += fn
        m.true_negatives += tn

        if language not in self._by_lang:
            self._by_lang[language] = EvalMetrics(vuln_class="ALL", language=language)
        m2 = self._by_lang[language]
        m2.true_positives += tp
        m2.false_positives += fp
        m2.false_negatives += fn
        m2.true_negatives += tn

    def summary(self) -> dict[str, Any]:
        return {
            "global": self._global.to_dict(),
            "per_class": [m.to_dict() for m in self._by_class.values()],
            "per_language": [m.to_dict() for m in self._by_lang.values()],
            "total_tests": (
                self._global.true_positives
                + self._global.false_positives
                + self._global.false_negatives
                + self._global.true_negatives
            ),
        }

    def meets_target(self, target_precision: float = 0.5, target_recall: float = 0.4) -> bool:
        return self._global.precision >= target_precision and self._global.recall >= target_recall

    def print_report(self):
        print("\n" + "=" * 60)
        print("  EVALUATION RESULTS")
        print("=" * 60)
        s = self.summary()
        g = s["global"]
        print(f"\n  Global Metrics:")
        print(f"    Precision: {g['precision']:.2%}  ({g['tp']}/{g['tp'] + g['fp']})")
        print(f"    Recall:    {g['recall']:.2%}  ({g['tp']}/{g['tp'] + g['fn']})")
        print(f"    F1 Score:  {g['f1']:.2%}")
        print(f"    Accuracy:  {g['accuracy']:.2%}")
        print(f"    Tests:     {s['total_tests']}")

        if s["per_class"]:
            print(f"\n  Per Vulnerability Class:")
            print(f"  {'Class':<25} {'Precision':<12} {'Recall':<12} {'F1':<10}")
            for m in sorted(s["per_class"], key=lambda x: x["f1"], reverse=True):
                print(f"  {m['vuln_class']:<25} {m['precision']:<12.2%} {m['recall']:<12.2%} {m['f1']:<10.2%}")

        if s["per_language"]:
            print(f"\n  Per Language:")
            print(f"  {'Language':<15} {'Precision':<12} {'Recall':<12} {'F1':<10}")
            for m in sorted(s["per_language"], key=lambda x: x["f1"], reverse=True):
                print(f"  {m['language']:<15} {m['precision']:<12.2%} {m['recall']:<12.2%} {m['f1']:<10.2%}")

        print("=" * 60)
