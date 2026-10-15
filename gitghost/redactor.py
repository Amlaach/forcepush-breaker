"""
Entropy Detector and Strict Secret Redactor.

Calculates Shannon entropy, detects sensitive tokens and credentials
via high-precision regex patterns, and enforces strict redaction so that raw secrets
are NEVER emitted in terminal output, exported reports, or AI prompts.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


