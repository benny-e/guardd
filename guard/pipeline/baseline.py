from __future__ import annotations

from dataclasses import dataclass, field

from guard.pipeline.aggregator import WindowState


@dataclass(slots=True)
class BaselineState:
    known_comms: set[str] = field(default_factory=set)
    known_files: set[str] = field(default_factory=set)
    known_parent_child: set[tuple[int, str]] = field(default_factory=set)

    def new_comms(self, window: WindowState) -> list[str]:
        return sorted(comm for comm in window.unique_comms if comm not in self.known_comms)

    def new_files(self, window: WindowState) -> list[str]:
        return sorted(path for path in window.unique_files if path not in self.known_files)

    def count_new_comms(self, window: WindowState) -> int:
        return len(self.new_comms(window))

    def count_new_files(self, window: WindowState) -> int:
        return len(self.new_files(window))

    def observe_window(self, window: WindowState) -> None:
        self.known_comms.update(window.unique_comms)
        self.known_files.update(window.unique_files)
        self.known_parent_child.update(window.unique_parent_child)

    def new_parent_child(self, window: WindowState) -> list[tuple[int, str]]:
        return sorted(
            pair for pair in window.unique_parent_child
            if pair not in self.known_parent_child
        )

    def count_new_parent_child(self, window: WindowState) -> int:
        return len(self.new_parent_child(window))

    def to_dict(self) -> dict[str, object]:
        return {
            "known_comms": sorted(self.known_comms),
            "known_files": sorted(self.known_files),
            "known_parent_child": [
                {"ppid": ppid, "comm": comm}
                for ppid, comm in sorted(self.known_parent_child)
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "BaselineState":
        known_comms = {str(x) for x in data.get("known_comms", [])}
        known_files = {str(x) for x in data.get("known_files", [])}

        raw_pairs = data.get("known_parent_child", [])
        known_parent_child = {
            (int(item["ppid"]), str(item["comm"]))
            for item in raw_pairs
        }

        return cls(
            known_comms=known_comms,
            known_files=known_files,
            known_parent_child=known_parent_child,
        )
