from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://medusa:medusa@postgres:5432/medusa"
    kubeconfig_path: str | None = None
    k8s_in_cluster: bool = False
    fsc_cr_namespace: str = "default"
    fsc_default_max_snapshots: int = 3
    fsc_default_interval: str = "5s"
    fsc_default_max_duration: str = "2m"
    fsc_integrity_algorithm: str = "sha256"
    min_alert_priority: str = "warning"
    idempotency_window_seconds: int = 60

    # host path inside kubelet to path inside medusa-api container
    checkpoint_host_prefix: str = "/var/lib/kubelet/checkpoints"
    checkpoint_container_path: str = "/checkpoints"
    kubeconfig_path: str = "/kube/config"

settings = Settings()

def get_settings() -> Settings:
    return settings