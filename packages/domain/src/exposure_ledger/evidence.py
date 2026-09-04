"""Immutable source provenance shared by evidence acquisition adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class Source:
    identity: str
    authority: str
    location: str


@dataclass(frozen=True, slots=True)
class EvidencePassage:
    identity: str
    kind: str
    content: str


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    identity: str
    source: Source
    captured_at: datetime
    content_digest: str
    attribution: str
    aliases: tuple[str, ...]
    payload_identity: str
    content: str
    passages: tuple[EvidencePassage, ...]


class SourceAdapter(Protocol):
    """Convert one captured provider payload into immutable evidence."""

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        captured_at: datetime,
        content: str | None = None,
    ) -> EvidenceRecord: ...
