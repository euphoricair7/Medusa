from fastapi import APIRouter, Request
import httpx

router = APIRouter()

@router.get("/")
async def get_alerts():
    return []

@router.post("/falco")
async def create_falco_alert(alert: dict, request: Request):
    print(f"Received Falco alert: {alert}")

    # Forward to forensic checkpointing if priority is high enough
    priority = alert.get("priority", "debug").lower()
    if priority in ["critical", "error", "warning"]:
        
        # The request to the forensic endpoint needs container_name, pod_name, and namespace.
        # Falco's output_fields should have this, but let's make sure.
        # For now, I'll extract what I can from the alert.
        output_fields = alert.get("output_fields", {})
        container_name = output_fields.get("k8s.pod.container.name") or output_fields.get("container.name")
        pod_name = output_fields.get("k8s.pod.name")
        namespace = output_fields.get("k8s.ns.name")

        # This is a simplification. In a real scenario, you'd have a more robust
        # way to get these details if they are not in the alert.
        if container_name and pod_name and namespace:
            forensic_request_body = {
                "rule": alert.get("rule"),
                "priority": alert.get("priority"),
                "output": alert.get("output"),
                "output_fields": output_fields,
                "tags": alert.get("tags"),
                "container_name": container_name,
                "pod_name": pod_name,
                "namespace": namespace,
            }

            forensic_url = request.url_for("create_falco_alert").replace("/alerts/falco", "/forensic/forensic-checkpoint")
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(forensic_url, json=forensic_request_body)
                    response.raise_for_status()
                    print(f"Forwarded to forensic checkpointing, status: {response.status_code}")
                except httpx.RequestError as e:
                    print(f"Error forwarding to forensic checkpointing: {e}")
        else:
            print("Could not forward to forensic checkpointing: missing container/pod/namespace info.")


    return {"status": "ok"}