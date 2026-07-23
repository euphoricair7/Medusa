import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forensic_service import process_trigger_forensic
from models.forensic import ForensicCheckpointStatus
from helpers import make_event


@pytest.mark.asyncio
@patch("forensic_service.forensic_snapshot_chain_exists", return_value=True)
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_duplicate_alert(mock_find, mock_submit, mock_exists):
    """
    Test that a duplicate alert returns the existing event.
    """
    existing = make_event(phase=ForensicCheckpointStatus.queued.value)
    mock_find.return_value = existing

    result = await process_trigger_forensic(
        AsyncMock(),
        alert_id=existing.alert_id,
        rule="manual",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    assert result is existing
    mock_submit.assert_not_called()


@pytest.mark.asyncio
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_new_alert(mock_find, mock_submit):
    """
    Test that a new alert creates a row and then creates a CR.
    """
    mock_find.return_value = None
    mock_submit.return_value = make_event(phase=ForensicCheckpointStatus.queued.value)

    session = MagicMock()
    session.flush = AsyncMock()

    await process_trigger_forensic(
        session,
        alert_id=uuid.uuid4(),
        rule="manual",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    session.add.assert_called_once()
    session.flush.assert_called_once()
    mock_submit.assert_called_once()


@pytest.mark.asyncio
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_two_alerts(mock_find, mock_submit):
    """
    Test that two alerts for the same pod create two events.
    """
    mock_find.return_value = None
    mock_submit.side_effect = lambda _session, **kwargs: kwargs["event"]

    session = MagicMock()
    session.flush = AsyncMock()

    trigger_kwargs = dict(
        rule="Terminal shell in container",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    await process_trigger_forensic(session, alert_id=uuid.uuid4(), **trigger_kwargs)
    await process_trigger_forensic(session, alert_id=uuid.uuid4(), **trigger_kwargs)

    assert session.add.call_count == 2
    assert session.flush.call_count == 2
    assert mock_submit.call_count == 2