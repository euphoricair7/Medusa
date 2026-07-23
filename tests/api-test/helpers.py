import uuid

from models.forensic import ForensicEvent


def make_event(*, phase: str, cr_name: str | None = "fsc-manual-abc12345") -> ForensicEvent:
    return ForensicEvent(
        id=uuid.uuid4(),
        alert_id=uuid.uuid4(),
        pod_name="nginx",
        namespace="default",
        container_name="nginx",
        phase=phase,
        operator_cr_name=cr_name,
        idempotency_key="dummy",
    )