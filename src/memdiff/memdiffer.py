"""
Provide memory diff capabilities by leveraging dirty flags

Note:
- Full dump is better for first dump as if a page is dirty we diff the content
of the page with the previous full dump instead of adding the whole page to the diff
"""

import logging
import os
import re
import struct
from tqdm import tqdm
from typing import Dict, List, Optional, Set, Union

LOGGER = logging.getLogger(__name__)


MAPS_LINE_PATTERN = re.compile(r"([0-9a-f]{8,128})-([0-9a-f]{8,128}) ([-r])([-w])([-x])([sp]) ([0-9a-f]{8,128}) ([0-9a-f:]{5}) ([0-9]+)\s*(.*)")

CPU_WORD_SIZE_BYTES = 8

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")  # Often 4kB

PAGEMAP_ENTRY_SIZE = 8

DEFAULT_MIN_DIFF_LENGTH_BYTES = int(os.environ.get("MIN_DIFF_LENGTH_BYTES")) if os.environ.get("MIN_DIFF_LENGTH_BYTES") else None

DEFAULT_MEM_REGIONS = set(os.environ.get("MEM_REGIONS").split(",")) if os.environ.get("MEM_REGIONS") else set()


class MemorySnapshot():
    """
    This class represents a memory snapshot (either full or partial, i.e., dirty pages only) or
    a reset event (if self.dump_type == "rst")
    """
    def __init__(self, pid: int, dump_type: str, event_id: str, post_dump_reset: bool = False) -> None:
        """
        Create a memory snapshot (memory dump will be done is PID is not null)
        If dump type is rst, only a reset of dirty flags will be done
        """
        # Store parameters
        self.pid = pid
        assert dump_type in ("full", "partial", "rst"), f"Bad dump type '{dump_type}'"
        self.dump_type = dump_type
        self.event_id = event_id
        self.post_dump_reset = post_dump_reset

        # Store regions
        self.regions: Dict[str, Dict[str, Union[str, int, Dict[int, bytes]]]] = {}

        # Size (in bytes) of the dump
        self.size: int = 0

        # Dump pages (full or dirty pages only)
        if self.pid:  # PID can be None, e.g., in unittest
            if self.dump_type in ("full", "partial"):
                self.dump()
                if self.post_dump_reset:
                    self.reset_dirty_flags()
            else:  # self.dump_type == "rst"
                self.reset_dirty_flags()

    def __eq__(self, __o: object) -> bool:
        """
        2 dumps are equal iif regions and pages are equal
        """
        return self.regions == __o.regions and self.regions["pages"] == __o.regions["pages"]

    def __repr__(self) -> str:
        return f"MemorySnapshot(type={self.dump_type}, " \
            f"event_id={self.event_id}, " \
            f"post_dump_rst={'yes' if self.post_dump_reset else 'no'})"

    def reset_dirty_flags(self) -> None:
        """
        Reset dirty flags
        """
        with open(f"/proc/{self.pid}/clear_refs", "wt") as fd:
            fd.write("4")
        LOGGER.debug("Dirty flags have been reset for PID %d (%s)", self.pid, self.event_id)

    def dump(self, mem_regions: Set[str] = DEFAULT_MEM_REGIONS) -> None:
        """
        Fill self.regions and self.size
        with respect to self.dump_type

        Only writable regions will be dumped
        If mem_regions is defined, only regions with name in mem_regions will be dumped
        e.g., "" for anonymous regions, "[heap]" for heap only, etc.
        """
        maps_file_path = f"/proc/{self.pid}/maps"
        with open(maps_file_path, 'r') as map_fd:
            for line_index, line in enumerate(map_fd.readlines()):  # for each mapped region
                match = MAPS_LINE_PATTERN.match(line)
                if not match:
                    LOGGER.warning("Fail to parse line '%s' in %s", line, maps_file_path)
                    continue
                if match.group(4) == 'w':  # writable region
                    # LOGGER.debug("line: %s", line)
                    if mem_regions and match.group(10) not in mem_regions:
                        continue

                    # LOGGER.debug("Processing memory region '%s'", match.group(10))
                    start = int(match.group(1), 16)
                    end = int(match.group(2), 16)
                    self.regions[start] = {
                        "start": start,
                        "end": end,
                        "path": match.group(10),
                        "index": line_index,
                        "pages": {}
                    }

        pagemap_file_path = f"/proc/{self.pid}/pagemap"
        mem_file_path = f"/proc/{self.pid}/mem"
        with open(pagemap_file_path, 'rb') as pagemap_fd, open(mem_file_path, 'rb', 0) as mem_fd:
            for region in self.regions.values():
                # LOGGER.debug("Processing region %s...", region)

                for page_start_addr in range(region["start"], region["end"], PAGE_SIZE):
                    # LOGGER.debug("Checking page %s...", page_start_addr)

                    # Find offset of this page in pagemap file
                    pagemap_offset = int((page_start_addr / PAGE_SIZE) * PAGEMAP_ENTRY_SIZE)

                    pagemap_fd.seek(pagemap_offset, 0)
                    pagemap_entry_bytes = pagemap_fd.read(PAGEMAP_ENTRY_SIZE)
                    pagemap_entry_int = struct.unpack('Q', pagemap_entry_bytes)[0]

                    is_present = ((pagemap_entry_int >> 63) & 1) != 0
                    if not is_present:
                        continue

                    if self.dump_type == "full":  # Dump all pages
                        mem_fd.seek(page_start_addr, 0)
                        region["pages"][page_start_addr] = mem_fd.read(PAGE_SIZE)
                        self.size += PAGE_SIZE
                    else:  # Dump dirty pages only
                        # Bit 55 set = pte is soft-dirty
                        is_dirty = ((pagemap_entry_int >> 55) & 1) != 0
                        if is_dirty:
                            # LOGGER.debug("Page '%s' has soft-dirty flag", page_start_addr)
                            mem_fd.seek(page_start_addr, 0)
                            try:
                                region["pages"][page_start_addr] = mem_fd.read(PAGE_SIZE)
                                self.size += PAGE_SIZE
                            except OSError:
                                LOGGER.warning("Fail to read page %d", page_start_addr)
        
        LOGGER.debug(
            "%s dump done for PID %d (%s): %d pages (%0.3f kB)",
            self.dump_type, self.pid, self.event_id, int(self.size / PAGE_SIZE), self.size / 1024
        )


class MemoryDiffer():
    """
    Provide memory diff capabilities by leveraging dirty flags
    """
    def __init__(self, pid: int, dump_method: str = "full-partial-rst") -> None:
        """
        Initialize a MemoryDiffer
        """
        # Dump methods: see paper for details
        self.pid = pid
        self.dump_method = dump_method
        assert dump_method in (
            "full-full", "rst-partial", "rst-partial-rst", "full-partial", "full-partial-rst"
        ), f"Bad dump method '{dump_method}'"

        # key is event name
        # e.g., {sip}{sport}{dip}{dport}_begin
        # value is index in self.snapshots
        self.events: Dict[str, int] = {}

        # List of memory snapshots (dump order is preserved)
        self.snapshots: List[MemorySnapshot] = []

        # Number of running (aka in-flight) handshakes
        # +1 on HS begin, -1 on HS end
        self.running_hs: int = 0
    
    def snap(self, event_id: str, first: Optional[bool] = None):
        """
        Do required actions with respect to self.dump_method

        Parameters:
        event_id: ID of the snapshot, e.g., begin{sip}{sport}{dip}{dport}
        first: indicate whether it's the beginning or end of HS
        (used to inc/dec self.running_hs). Optional

        TODO: Cleanup self.snapshots at some point
        """
        LOGGER.debug("Snapshotting for event %s...", event_id)

        if self.events.get(event_id) is not None:
            raise ValueError("Event ID '%s' already taken")
        
        if self.dump_method == "full-full":
            self.snapshots.append(
                MemorySnapshot(
                    self.pid,
                    "full",
                    event_id
                )
            )

        elif self.dump_method in ("rst-partial", "rst-partial-rst"):
            if not self.snapshots:
                self.snapshots.append(
                    MemorySnapshot(
                        self.pid,
                        "rst",  # Only a reset (no mem dump)
                        event_id
                    )
                )
            else:
                self.snapshots.append(
                    MemorySnapshot(
                        self.pid,
                        "partial",
                        event_id,
                        post_dump_reset=self.dump_method == "rst-partial-rst"
                    )
                )

        elif self.dump_method in ("full-partial", "full-partial-rst"):
            if not self.snapshots:
                self.snapshots.append(
                    MemorySnapshot(
                        self.pid,
                        "full",
                        event_id,
                        post_dump_reset=True
                    )
                )
            else:
                self.snapshots.append(
                    MemorySnapshot(
                        self.pid,
                        "partial",
                        event_id,
                        post_dump_reset=self.dump_method == "full-partial-rst"
                    )
                )

        self.events[event_id] = len(self.snapshots) - 1

        if first is not None:
            self.running_hs += 1 if first else -1

    def diff(self, start_event_id: str, stop_event_id: str) -> Dict[str, Dict[str, Union[str, int, bytes]]]:
        """
        We compute the diff between all memory snapshots between start and stop events

        Hypothesis:
        - No full dump between start and stop events except start or stop event (optionally)
        TODO: Can be not verified with full-full and overlapping sessions
        """
        LOGGER.debug("Generating diff from %s to %s", start_event_id, stop_event_id)

        snap_id_range = range(self.events[start_event_id], self.events[stop_event_id]+1)
        if len(snap_id_range) < 2:
            raise ValueError("No snapshot: same event or bad events ordering")
        snapshots = self.snapshots[snap_id_range[0]:snap_id_range[-1]+1]
        LOGGER.debug("Snapshots: %s", snapshots)

        start_regions = {}
        end_regions = {}

        start_regions.update(snapshots[0].regions)  # Can be {} is snap is RST only
        for snap in snapshots[1:]:  # All events except first event
            for region_id in snap.regions:
                if end_regions.get(region_id):
                    end_regions[region_id]["pages"].update(snap.regions[region_id]["pages"])
                else:
                    end_regions[region_id] = snap.regions[region_id]
        # LOGGER.debug("start_regions: %s, end_regions: %s", start_regions, end_regions)

        diff = {
            region_id: {
                "diff": b"",
                "path": region["path"],
                "index": region["index"]
            }
            for region_id, region in end_regions.items()
        }

        for region_id in tqdm(start_regions.keys() & end_regions.keys(), desc=f"{start_event_id}...{stop_event_id}", leave=False):
            # Existing but updated pages: diff page content
            for page_addr in start_regions[region_id]["pages"].keys() & end_regions[region_id]["pages"].keys():
                # LOGGER.debug("Page '%d' exists in start and stop events", page_addr)
                for byte_idx in range(0, PAGE_SIZE, CPU_WORD_SIZE_BYTES):
                    if start_regions[region_id]["pages"][page_addr][byte_idx:byte_idx+CPU_WORD_SIZE_BYTES] != end_regions[region_id]["pages"][page_addr][byte_idx:byte_idx+CPU_WORD_SIZE_BYTES]:
                        # LOGGER.debug("Adding '%s' to diff", end_regions["pages"][page_addr][byte_idx:byte_idx+CPU_WORD_SIZE_BYTES])
                        diff[region_id]["diff"] += end_regions[region_id]["pages"][page_addr][byte_idx:byte_idx+CPU_WORD_SIZE_BYTES]

            # New pages or no initial dump: add full page
            for page_addr in end_regions[region_id]["pages"].keys() - start_regions[region_id]["pages"].keys():
                # LOGGER.debug("Page '%d' is a new page", page_addr)
                diff[region_id]["diff"] += end_regions[region_id]["pages"][page_addr]
        
        # New regions
        for region_id in end_regions.keys() - start_regions.keys():
            for page_addr in end_regions[region_id]["pages"].keys():
                # LOGGER.debug("Page '%d' is a new page", page_addr)
                diff[region_id]["diff"] += end_regions[region_id]["pages"][page_addr]

        diff_size = sum((len(region["diff"]) for region in diff.values()))
        LOGGER.debug("Diff size is %0.3fkB", diff_size / 1024)

        assert diff_size, "Empty diff"

        # Return full dump instead of dump
        if os.environ.get("DEBUG_NO_DIFF", "false") == "true":
            LOGGER.warning("Returning *all* end snapshot pages instead of diff: high performance impact!")
            for region_id in end_regions:
                diff[region_id]["diff"] = b""
                for page_addr in end_regions[region_id]["pages"].keys():
                    diff[region_id]["diff"] += end_regions[region_id]["pages"][page_addr]

        # Save memory dump for debugging
        save_diff_path = os.environ.get("DEBUG_SAVE_DIFF")
        if save_diff_path:
            LOGGER.info("Saving memory dump for debugging to %s", save_diff_path)
            with open(save_diff_path, "wt") as diff_fd:
                for region in diff.values():
                    diff_fd.write(f"{region['index']} {region['path']} {region['diff'].hex()}\n")
            os.chmod(save_diff_path, 0o644)

        return diff

    def get_snapshot(self, event_id: str) -> MemorySnapshot:
        """
        Return memory snapshot associated to event ID
        or raise ValueError if event does not exist
        """
        try:
            snapshot = self.snapshots[self.events[event_id]]
        except KeyError:
            raise ValueError("Fail to find event ID '%s'", event_id)
        return snapshot


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pid> <dump_method>")
        print("Dump methods: full-full, rst-partial, rst-partial-rst, full-partial, full-partial-rst")
        sys.exit(2)

    memdiff = MemoryDiffer(int(sys.argv[1]), sys.argv[2])
    try:
        while True:
            event_id = input("Enter event ID and press Enter to take a snapshot (or CTRL+C to exit)\n")
            memdiff.snap(event_id, None)
    except KeyboardInterrupt:
        # Print diff in hex
        for i in range(1, len(memdiff.snaphots)):
            diff = memdiff.diff(memdiff.snaphots[i-1].event_id, memdiff.snaphots[i].event_id)
            print(f"{memdiff.snaphots[i-1].event_id}->{memdiff.snaphots[i].event_id}")
            print(f"HEX: {''.join((region['diff'].hex() for region in diff.values()))}")
            print("ASCII: ", end="")
            for region in diff.values():
                for b in region["diff"]:
                    try:
                        if b >= 30 and b <= 122:  # Only characters that looks pretty (arbitrary!)
                            print(chr(b), end="")
                    except ValueError:
                        pass
            print()
            print("---")
