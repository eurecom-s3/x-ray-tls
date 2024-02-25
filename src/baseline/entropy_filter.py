"""
This module implements the baseline approach
"""

import logging
import math
from typing import Dict

from tqdm import tqdm

from src.memdiff.memdiffer import MemorySnapshot

LOGGER = logging.getLogger(__name__)


CPU_WORD_SIZE_BYTES = 8
SECRET_SIZE_BYTES = 48


def entropy(string: str) -> float:
    """
    Calculates the Shannon entropy of a string
    """
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def baseline_entropy_filter(snapshot: MemorySnapshot, entropy_threshold: float = 3.6) -> Dict[str, any]:
    """
    Return figures about the baseline approach
    """
    assert snapshot.dump_type == "full", "Not a full snapshot"

    entropy_filter_size_bytes = 0
    for region in tqdm(snapshot.regions.values(), desc=f"{snapshot}_baseline", leave=False):
        for page_addr in region["pages"].keys():
            page_hex = region["pages"][page_addr].hex()
            for i in range(0, len(page_hex) - SECRET_SIZE_BYTES * 2, CPU_WORD_SIZE_BYTES * 2):  # 1 byte = 2 chars in hex
                if entropy(page_hex[i:i + SECRET_SIZE_BYTES * 2]) >= entropy_threshold:
                    entropy_filter_size_bytes += SECRET_SIZE_BYTES

    return {
        "entropy_filter_size_bytes": entropy_filter_size_bytes,
        "entropy_filter_key_candidates_count": int(entropy_filter_size_bytes / 48),
        "original_size_bytes": snapshot.size,
        "original_key_candidates_count": int(snapshot.size / 48),
    }
