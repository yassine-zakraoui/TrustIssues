"""Agent long-term memory stored in simulator state with provenance-derived trust."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.core.state import RecordMeta, WorldState

MEMORY_COLLECTION = "memory"


@dataclass(frozen=True)
class MemoryEntry:
    entry_id: str
    content: str
    trust_level: TrustLevel
    written_at_step: int


class AgentMemory:
    def __init__(self, state: WorldState) -> None:
        self._state = state

    def write(self, content: str, trust_level: TrustLevel, step_id: int) -> MemoryEntry:
        meta = RecordMeta(SourceType.MEMORY, trust_level, "agent_memory", Sensitivity.INTERNAL)
        entry_id = self._state.insert(MEMORY_COLLECTION, "MEM", {"content": content, "written_at_step": step_id}, meta)
        return MemoryEntry(entry_id, content, trust_level, step_id)

    def recall(self) -> list[MemoryEntry]:
        entries = []
        for record in self._state.table(MEMORY_COLLECTION).values():
            meta = RecordMeta.from_dict(record["_meta"])
            entries.append(
                MemoryEntry(
                    entry_id=str(record["id"]),
                    content=str(record["content"]),
                    trust_level=meta.trust_level,
                    written_at_step=int(record.get("written_at_step", 0)),
                )
            )
        return sorted(entries, key=lambda entry: entry.entry_id)
