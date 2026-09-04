from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from exposure_ledger import (
    CapturedSourcePayload,
    OsvBatchResponse,
    OsvResponseRejected,
    OsvSourceAdapter,
)


def test_osv_adapter_captures_stable_immutable_evidence_provenance() -> None:
    adapter = OsvSourceAdapter()
    payload = {
        "id": "PYSEC-2026-50",
        "aliases": ["CVE-2026-5000"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.1"}],
                    }
                ],
            }
        ],
    }
    captured_at = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)
    captured_content = (
        '{"affected":[{"package":{"ecosystem":"PyPI","name":"demo-pkg"},'
        '"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.1"}],'
        '"type":"ECOSYSTEM"}]}],"aliases":["CVE-2026-5000"],'
        '"id":"PYSEC-2026-50"}'
    )

    evidence = adapter.capture(
        payload,
        capture=CapturedSourcePayload(content=captured_content, captured_at=captured_at),
    )
    reordered = adapter.capture(
        {"affected": payload["affected"], "id": payload["id"], "aliases": payload["aliases"]},
        capture=CapturedSourcePayload(
            content=captured_content,
            captured_at=datetime(2026, 9, 3, 12, 31, tzinfo=UTC),
        ),
    )

    assert evidence.source.identity == "osv"
    assert evidence.source.authority == "Open Source Vulnerabilities"
    assert evidence.source.location == "https://api.osv.dev/v1/vulns/PYSEC-2026-50"
    assert evidence.captured_at == captured_at
    assert evidence.content_digest == (
        "sha256:d1f4d3d676513b1c92048e7ac16ecfb86fb63d227f13115e77b8b01e3e2c8d7e"
    )
    assert evidence.attribution == "Open Source Vulnerabilities (OSV)"
    assert evidence.aliases == ("CVE-2026-5000", "PYSEC-2026-50")
    assert evidence.payload_identity == "PYSEC-2026-50"
    assert evidence.identity == reordered.identity
    assert evidence.content_digest == reordered.content_digest
    assert evidence.passages[0].kind == "affected"
    assert evidence.passages[0].selector == "/affected/0"
    assert evidence.passages[0].content == (
        '{"package":{"ecosystem":"PyPI","name":"demo-pkg"},"ranges":'
        '[{"events":[{"introduced":"0"},{"fixed":"1.1"}],"type":"ECOSYSTEM"}]}'
    )

    with pytest.raises(FrozenInstanceError):
        evidence.payload_identity = "changed"  # type: ignore[misc]


def test_osv_adapter_rejects_payload_without_provider_identity() -> None:
    with pytest.raises(OsvResponseRejected, match="identifier"):
        OsvSourceAdapter().capture(
            {"affected": []},
            capture=CapturedSourcePayload(
                content='{"affected":[]}',
                captured_at=datetime(2026, 9, 3, tzinfo=UTC),
            ),
        )


def test_osv_batch_rejects_parsed_records_without_captured_source_content() -> None:
    with pytest.raises(OsvResponseRejected, match="captured Source content"):
        OsvBatchResponse.capture(
            {"results": [{"vulns": [{"id": "PYSEC-2026-50", "affected": []}]}]},
            expected_results=1,
        )


def test_osv_adapter_rejects_duplicate_affected_members() -> None:
    content = (
        '{"id":"PYSEC-2026-50","affected":[{"package":{"ecosystem":"PyPI",'
        '"name":"wrong"}}],"affected":[{"package":{"ecosystem":"PyPI",'
        '"name":"demo-pkg"}}]}'
    )
    payload = {
        "id": "PYSEC-2026-50",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-pkg"}}],
    }

    with pytest.raises(OsvResponseRejected, match="repeats the 'affected' member"):
        OsvSourceAdapter().capture(
            payload,
            capture=CapturedSourcePayload(
                content=content,
                captured_at=datetime(2026, 9, 3, tzinfo=UTC),
            ),
        )
