"""
Unittests for memdiff.py
"""

import pytest

import src.memdiff.memdiffer as memdiffer
from src.memdiff.memdiffer import MemoryDiffer, MemorySnapshot

# Reduce page size and cpu word size for increased readability in unittest samples
memdiffer.PAGE_SIZE = 8
memdiffer.CPU_WORD_SIZE_BYTES = 2

# Helper function
def create_snapshots(test_snapshots):
    snapshots = []
    events = {}
    for test_snap in test_snapshots:
        mem_snap = MemorySnapshot(
            pid=None,
            dump_type=test_snap["dump_type"],
            event_id=test_snap["event_id"]
        )
        mem_snap.regions = test_snap["regions"]
        snapshots.append(mem_snap)
        events[test_snap["event_id"]] = len(snapshots) - 1
    return snapshots, events


def test_2_snaps_same_page():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababac"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    with pytest.raises(ValueError):
        memdiff.diff("event1", "event1")  # Same event
    with pytest.raises(ValueError):
        memdiff.diff("event2", "event1")  # Bad order
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ac"
        }
    }


def test_2_snaps_new_page():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        2: b"abababac"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"abababac"
        }
    }


def test_3_snaps_new_page():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab",
                        2: b"abababac"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event3",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab",
                        2: b"abababad",
                        3: b"xxxxxxxx"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"abababac"
        }
    }
    assert memdiff.diff("event2", "event3") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"adxxxxxxxx"
        }
    }
    assert memdiff.diff("event1", "event3") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"abababadxxxxxxxx"
        }
    }


def test_3_snaps():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababac"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event3",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababad"
                    }
                }
            } 
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ac"
        }
    }
    assert memdiff.diff("event2", "event3") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ad"
        }
    }
    assert memdiff.diff("event1", "event3") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ad"
        }
    }


def test_5_snaps():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababac"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event3",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababad"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event4",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababae"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event5",
            "regions": {
                1: {
                    "path": "",
                    "index": 0,
                    "pages": {
                        1: b"abababaf"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ac"
        }
    }
    assert memdiff.diff("event2", "event3") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ad"
        }
    }
    assert memdiff.diff("event3", "event4") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ae"
        }
    }
    assert memdiff.diff("event4", "event5") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"af"
        }
    }
    
    assert memdiff.diff("event2", "event4") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ae"
        }
    }
    assert memdiff.diff("event2", "event5") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"af"
        }
    }
    assert memdiff.diff("event1", "event4") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"ae"
        }
    }
    assert memdiff.diff("event1", "event5") == {
        1: {
            "path": "",
            "index": 0,
            "diff": b"af"
        }
    }


def test_2_snaps_new_region():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "region1",
                    "index": 1,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                2: {
                    "path": "region2",
                    "index": 2,
                    "pages": {
                        1: b"abababac"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        2: {
            "path": "region2",
            "index": 2,
            "diff": b"abababac"
        }
    }


def test_2_snaps_new_region():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "full",
            "event_id": "event1",
            "regions": {
                1: {
                    "path": "region1",
                    "index": 1,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "region1",
                    "index": 1,
                    "pages": {
                        1: b"abababac"
                    }
                },
                2: {
                    "path": "region2",
                    "index": 2,
                    "pages": {
                        2: b"abababac"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "region1",
            "index": 1,
            "diff": b"ac"
        },
        2: {
            "path": "region2",
            "index": 2,
            "diff": b"abababac"
        }
    }


def test_initial_rst():
    memdiff = MemoryDiffer(None)
    test_snapshots = [
        {
            "dump_type": "rst",
            "event_id": "event1",
            "regions": {}
        },
        {
            "dump_type": "partial",
            "event_id": "event2",
            "regions": {
                1: {
                    "path": "region1",
                    "index": 1,
                    "pages": {
                        1: b"abababab"
                    }
                }
            }
        }
    ]
    memdiff.snaphots, memdiff.events = create_snapshots(test_snapshots)
    assert memdiff.diff("event1", "event2") == {
        1: {
            "path": "region1",
            "index": 1,
            "diff": b"abababab"
        }
    }
