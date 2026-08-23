import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from helpers import make_event
from models.forensic import ForensicAnalysisRequest, ForensicCheckpointStatus
from routers.forensic import attach_checkpointctl_analysis


def _mock_session_returning(event):
    """SessionLocal context manager whose execute().scalars().first() returns event."""
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = None
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    result = MagicMock()
    result.scalars.return_value.first.return_value = event
    session.execute = AsyncMock(return_value=result)
    return session


@pytest.mark.asyncio
@patch("routers.forensic.SessionLocal")
async def test_attach_analysis_writes_checkpointctl(mock_session_local):
    event = make_event(phase=ForensicCheckpointStatus.success.value)
    event.raw_report = None
    mock_session_local.return_value = _mock_session_returning(event)

    body = ForensicAnalysisRequest(
        checkpoint_path="/var/lib/kubelet/checkpoints/example.tar",
        report={"processes": [{"pid": 1, "comm": "bash"}]},
    )
    out = await attach_checkpointctl_analysis(event.id, body)

    assert out.raw_report["checkpointctl"]["checkpoint_path"] == body.checkpoint_path
    assert out.raw_report["checkpointctl"]["report"] == body.report
    assert out.raw_report["checkpointctl"]["analyzer"] == "checkpointctl"
    assert "analyzed_at" in out.raw_report["checkpointctl"]
    mock_session_local.return_value.commit.assert_awaited()


@pytest.mark.asyncio
@patch("routers.forensic.SessionLocal")
async def test_attach_analysis_keeps_operator(mock_session_local):
    event = make_event(phase=ForensicCheckpointStatus.success.value)
    event.raw_report = {"operator": {"operator_phase": "Completed", "snapshot_count": 1}}
    mock_session_local.return_value = _mock_session_returning(event)

    body = ForensicAnalysisRequest(
        checkpoint_path="/checkpoints/x.tar",
        node_name="kind-control-plane",
        report={"processes": []},
    )
    out = await attach_checkpointctl_analysis(event.id, body)

    assert out.raw_report["operator"]["operator_phase"] == "Completed"
    assert out.raw_report["operator"]["snapshot_count"] == 1
    assert "checkpointctl" in out.raw_report
    assert out.raw_report["checkpointctl"]["node_name"] == "kind-control-plane"


@pytest.mark.asyncio
@patch("routers.forensic.SessionLocal")
async def test_attach_analysis_404_when_missing(mock_session_local):
    mock_session_local.return_value = _mock_session_returning(None)

    body = ForensicAnalysisRequest(
        checkpoint_path="/checkpoints/x.tar",
        report={},
    )
    with pytest.raises(HTTPException) as exc_info:
        await attach_checkpointctl_analysis(uuid.uuid4(), body)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
@patch("routers.forensic.SessionLocal")
async def test_attach_analysis_replaces_previous_checkpointctl(mock_session_local):
    event = make_event(phase=ForensicCheckpointStatus.success.value)
    event.raw_report = {
        "operator": {"operator_phase": "Completed"},
        "checkpointctl": {
            "checkpoint_path": "/old.tar",
            "analyzer": "checkpointctl",
            "report": {"processes": [{"pid": 99}]},
        },
    }
    mock_session_local.return_value = _mock_session_returning(event)

    body = ForensicAnalysisRequest(
        checkpoint_path="/new.tar",
        report={"processes": [{"pid": 1}]},
    )
    out = await attach_checkpointctl_analysis(event.id, body)

    assert out.raw_report["operator"]["operator_phase"] == "Completed"
    assert out.raw_report["checkpointctl"]["checkpoint_path"] == "/new.tar"
    assert out.raw_report["checkpointctl"]["report"] == {"processes": [{"pid": 1}]}
