from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AutoPentest AI"
    database_url: str = "sqlite:///./autopentest.db"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False

    # Comma-separated browser origins allowed by CORS (e.g. your frontend's
    # dev URL). Empty = CORS middleware disabled.
    cors_origins: str = ""

    # --- Scope / safety -----------------------------------------------------
    # Allow loopback/private/non-public targets. Local development only.
    # Cloud metadata and link-local addresses stay blocked regardless.
    allow_private_targets: bool = False

    # --- Scanner execution --------------------------------------------------
    # Absolute executable paths. Empty = look the tool up on a fixed safe PATH.
    nmap_path: str = ""
    nmap_timeout_seconds: int = 900
    nuclei_path: str = ""
    nuclei_timeout_seconds: int = 1800
    ffuf_path: str = ""
    # Hard ceiling per FFUF invocation (one per discovered web service).
    ffuf_timeout_seconds: int = 600
    # OWASP ZAP baseline (passive) runs in Docker. Server-side only, never API.
    zap_docker_path: str = ""  # empty = find `docker` on the fixed safe PATH
    zap_docker_image: str = "zaproxy/zap-stable"
    # Docker network for the ZAP container. Empty = Docker's default bridge.
    # Lab use: "container:juice-shop" shares the Juice Shop container's network
    # so a loopback target (http://127.0.0.1:3000) resolves to that service.
    zap_docker_network: str = ""
    zap_memory: str = "2g"
    zap_timeout_seconds: int = 900
    # Raw tool output kept per scanner run (bytes); anything beyond is truncated.
    max_tool_output_bytes: int = 5_000_000

    # --- Claude AI analyst (Phase 3) ----------------------------------------
    # Loaded from the environment or .env like every other setting, and passed
    # explicitly to the SDK client so it always wins over any OAuth/`ant`
    # profile on the machine. SecretStr keeps it masked in repr/logs/dumps.
    # Empty or unset = not configured (AI analysis then fails closed).
    anthropic_api_key: SecretStr | None = None
    # Verified available on this account via the Models API on 2026-11-13.
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = "high"  # low | medium | high | xhigh | max
    anthropic_max_tokens: int = 64000  # streamed, so large values are safe
    anthropic_timeout_seconds: float = 900
    # Data minimization: at most this many findings (highest severity first),
    # and long text fields are truncated before being sent to Claude.
    ai_max_findings: int = 150
    ai_max_field_chars: int = 1500

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("anthropic_api_key", mode="before")
    @classmethod
    def _blank_key_is_unset(cls, value):
        if value is None:
            return None
        raw = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        raw = raw.strip()
        return raw or None

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
