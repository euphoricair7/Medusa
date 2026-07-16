from kubernetes import client, config
from config import settings

FSC_GROUP = "criu.org"
FSC_VERSION = "v1"
FSC_PLURAL = "forensicsnapshotchains"
FORENSIC_EVENT_LABEL = "medusa.criu.org/forensic-event-id"

_client: "K8sClient | None" = None

def get_k8s_client() -> "K8sClient":
    global _client
    if _client is None:
        _client = K8sClient()
    return _client


class K8sClient:
    def __init__(self) -> None:
        settings = get_settings()
        if settings.k8s_in_cluster:
            config.load_incluster_config()
        else:
            path = settings.kubeconfig_path or "/kube/config"
            config.load_kube_config(config_file=path)
        self._core = client.CoreV1Api()
        self._custom = client.CustomObjectsApi()
        self._settings = settings
    
    def get_pod(self, namespace: str, pod_name: str):
        return self._core.read_namespaced_pod(name=pod_name, namespace=namespace)
    
    def create_forensic_snapshot_chain(self, namespace: str, body: dict) -> dict:
        return self._custom.create_namespaced_custom_object(
            group=FSC_GROUP,
            version=FSC_VERSION,
            namespace=namespace,
            plural=FSC_PLURAL,
            body=body,
        )
    
    def list_forensic_snapshot_chains(self, namespace: str, label_selector: str | None = None) -> dict:
        return self._custom.list_namespaced_custom_object(
            group=FSC_GROUP,
            version=FSC_VERSION,
            namespace=namespace,
            plural=FSC_PLURAL,
            label_selector=label_selector,
        )
    def get_forensic_snapshot_chain(self, namespace: str, name: str) -> dict:
        return self._custom.get_namespaced_custom_object(
            group=FSC_GROUP,
            version=FSC_VERSION,
            namespace=namespace,
            plural=FSC_PLURAL,
            name=name,
        )

