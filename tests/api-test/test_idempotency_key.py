import uuid
from forensic_chain import make_idempotency_key


def test_idempotency_key_differs_by_alert_id():
    """
    Test that the idempotency key differs by alert id.
    """
    a1, a2 = uuid.uuid4(), uuid.uuid4()
    k1 = make_idempotency_key(a1, "default", "nginx", "nginx")
    k2 = make_idempotency_key(a2, "default", "nginx", "nginx")
    assert k1 != k2


def test_idempotency_key_stable_for_same_alert():
    """
    Test that the idempotency key is stable for the same alert.
    """
    alert_id = uuid.uuid4()
    k1 = make_idempotency_key(alert_id, "default", "nginx", "nginx")
    k2 = make_idempotency_key(alert_id, "default", "nginx", "nginx")
    assert k1 == k2


def test_idempotency_key_empty_container():
    """
    Test that the idempotency key is stable for the same alert.
    """
    alert_id = uuid.uuid4()
    k_none = make_idempotency_key(alert_id, "default", "nginx", None)
    k_empty = make_idempotency_key(alert_id, "default", "nginx", "")
    assert k_none == k_empty
