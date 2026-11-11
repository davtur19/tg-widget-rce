"""Small statistics helpers for matrix summaries.

The campaign reports a point estimate plus a one-sided 95 % Clopper-Pearson
lower bound (the same spirit as the rule of three).  Only the lower bound is
computed here; no claim is made beyond the measured count.
"""
from __future__ import annotations

import math


def binomial_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""

    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    # Sum the smaller tail to keep precision.
    if k > n / 2:
        return 1.0 - binomial_cdf(k - 1, n, p)
    total = 0.0
    for i in range(k, n + 1):
        total += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
    return min(1.0, max(0.0, total))


def binomial_cdf(k: int, n: int, p: float) -> float:
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    total = 0.0
    for i in range(0, k + 1):
        total += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
    return min(1.0, max(0.0, total))


def clopper_pearson_lower(k: int, n: int, confidence: float = 0.95) -> float:
    """One-sided Clopper-Pearson lower bound for k successes in n trials."""

    if n <= 0:
        return 0.0
    if k <= 0:
        return 0.0
    alpha = 1.0 - confidence
    if k >= n:
        # Lower bound solves p^n = alpha.
        return alpha ** (1.0 / n)
    low, high = 0.0, 1.0
    # Solve P(X >= k | p) = alpha.  The survival function increases with p,
    # so a value below alpha means the root is above the midpoint.
    for _ in range(80):
        mid = (low + high) / 2.0
        if binomial_sf(k, n, mid) < alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def summarize_counts(passed: int, total: int, confidence: float = 0.95) -> dict:
    return {
        "passed": passed,
        "total": total,
        "rate": (passed / total) if total else None,
        "cp_lower_95_one_sided": clopper_pearson_lower(passed, total, confidence),
        "method": "Clopper-Pearson lower bound, one-sided 95%",
    }
