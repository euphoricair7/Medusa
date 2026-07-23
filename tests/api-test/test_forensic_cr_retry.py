from unittest.mock import AsyncMock, patch

import pytest

from config import settings
from forensic_service import process_trigger_forensic
from helpers import make_event
from models.forensic import ForensicCheckpointStatus
from forensic_service import _submit_forensic_snapshot_chain_cr


@pytest.mark.asyncio
@patch("forensic_service.forensic_snapshot_chain_exists", return_value=False)
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_deleted_cr(mock_find, mock_submit, mock_exists):
    """
    Test that a deleted CR is recreated on the same row if the same idempotency key is used.
    """
    existing = make_event(phase=ForensicCheckpointStatus.success.value, cr_name="fsc-old")
    mock_find.return_value = existing
    mock_submit.return_value = existing

    await process_trigger_forensic(
        AsyncMock(),
        alert_id=existing.alert_id,
        rule="manual",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    mock_exists.assert_called_once_with(settings.fsc_cr_namespace, "fsc-old")
    assert mock_submit.call_args.kwargs["event"] is existing


@pytest.mark.asyncio
@patch("forensic_service.forensic_snapshot_chain_exists", return_value=True)
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_failed_phase_retry(mock_find, mock_submit, mock_exists):
    """
    Test that a failed phase is retried if the same idempotency key is used.
    """
    existing = make_event(phase=ForensicCheckpointStatus.failed.value)
    mock_find.return_value = existing

    await process_trigger_forensic(
        AsyncMock(),
        alert_id=existing.alert_id,
        rule="manual",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    mock_submit.assert_called_once()


@pytest.mark.asyncio
@patch("forensic_service.forensic_snapshot_chain_exists", return_value=False)
@patch("forensic_service._submit_forensic_snapshot_chain_cr", new_callable=AsyncMock)
@patch("forensic_service.find_by_idempotency_key", new_callable=AsyncMock)
async def test_queued_phase(mock_find, mock_submit, mock_exists):
    """
    Test that a queued phase is retried if the same idempotency key is used.
    """
    existing = make_event(phase=ForensicCheckpointStatus.queued.value, cr_name="fsc-gone")
    mock_find.return_value = existing
    mock_submit.return_value = existing

    await process_trigger_forensic(
        AsyncMock(),
        alert_id=existing.alert_id,
        rule="manual",
        priority="Critical",
        trigger_source="manual",
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
    )

    mock_exists.assert_called_once_with(settings.fsc_cr_namespace, "fsc-gone")
    mock_submit.assert_called_once()
    assert mock_submit.call_args.kwargs["event"] is existing


@pytest.mark.asyncio
@patch("forensic_service.create_forensic_snapshot_chain", return_value="fsc-manual-newcr01")
@patch("forensic_service.build_forensic_snapshot_chain_body", return_value={})
async def test_failed_phase_clear_error(mock_build, mock_create):
    """
    Test that a failed phase clears the CR create error on success.
    """

    event = make_event(phase=ForensicCheckpointStatus.failed.value)
    event.raw_report = {"cr_create_error": "409 Conflict"}

    session = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    await _submit_forensic_snapshot_chain_cr(
        session,
        event=event,
        namespace="default",
        pod_name="nginx",
        container_name="nginx",
        rule="manual",
        priority="Critical",
    )

    assert event.raw_report is None
    assert event.phase == ForensicCheckpointStatus.queued.value

