"""Immutable source provenance shared by evidence acquisition adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class Source:
    identity: str
    authority: str
    location: str


class EvidenceRelationship(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXTUAL = "contextual"


@dataclass(frozen=True, slots=True)
class EvidencePassage:
    identity: str
    kind: str
    selector: str
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


@dataclass(frozen=True, slots=True)
class CapturedSourcePayload:
    content: str
    captured_at: datetime


class CapturedJsonRejected(ValueError):
    """Captured JSON is invalid or has ambiguous duplicate object members."""


def load_captured_json(content: str) -> object:
    try:
        return json.loads(content, object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError as error:
        raise CapturedJsonRejected("Captured content must be valid JSON") from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CapturedJsonRejected(f"Captured content repeats the {key!r} member")
        result[key] = value
    return result


class SourceAdapter(Protocol):
    """Convert one captured provider payload into immutable evidence."""

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord: ...
