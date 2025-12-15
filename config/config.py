from __future__ import annotations

import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, model_validator

# Load .env if present
load_dotenv()


class ProviderSettings(BaseModel):
    base_url: str
    api_key: str
    model: str


class LLMSettings(BaseModel):
    timeout_seconds: int = Field(default=int(os.getenv("POCGEN_TIMEOUT", "60")))
    providers: Dict[str, ProviderSettings] = Field(default_factory=dict)
    default_provider: str = Field(default=os.getenv("POCGEN_DEFAULT_PROVIDER", "qwen"))

    @model_validator(mode="before")
    def populate_providers(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        providers = values.get("providers") or {}
        if not providers:
            providers = {
                "qwen": ProviderSettings(
                    base_url=os.getenv("POCGEN_QWEN_BASE_URL", "http://222.20.126.36:30000/v1"),
                    api_key=os.getenv("POCGEN_QWEN_API_KEY", "QWEN3@C402"),
                    model=os.getenv("POCGEN_QWEN_MODEL", "qwen"),
                ),
                "deepseek": ProviderSettings(
                    base_url=os.getenv("POCGEN_DS_BASE_URL", "http://222.20.126.32:30000/v1"),
                    api_key=os.getenv("POCGEN_DS_API_KEY", "DeepseekV3.1_32@C402"),
                    model=os.getenv("POCGEN_DS_MODEL", "deepseek"),
                ),
            }
        normalized: Dict[str, ProviderSettings] = {}
        for key, cfg in providers.items():
            cfg_model = cfg if isinstance(cfg, ProviderSettings) else ProviderSettings.model_validate(cfg)
            normalized[key.lower()] = cfg_model
        values["providers"] = normalized
        if "default_provider" not in values:
            values["default_provider"] = os.getenv("POCGEN_DEFAULT_PROVIDER", "qwen")
        return values

    @model_validator(mode="after")
    def ensure_default_provider(self) -> "LLMSettings":
        if not self.providers:
            raise ValueError("No LLM providers configured")
        default_key = (self.default_provider or "").lower()
        if default_key not in self.providers:
            default_key = next(iter(self.providers.keys()))
        self.default_provider = default_key
        return self


class AppSettings(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    save_dir: str = Field(
        default=os.getenv(
            "POCGEN_OUTPUT_DIR",
            os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "output")),
        )
    )
    collect_dir: str = Field(
        default=os.getenv(
            "POCGEN_COLLECT_DIR",
            os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "collect")),
        )
    )
    default_vuln_type: str = Field(default=os.getenv("POCGEN_VULN_TYPE", "command_injection_http"))
    attacker_url: str = Field(default=os.getenv("POCGEN_ATTACKER_URL", "http://192.168.6.1:6666/testpoc"))
    bridge_url: str | None = Field(default=os.getenv("POCGEN_BRIDGE_URL", "http://127.0.0.1:7002"))
    http_proxy: str | None = Field(default=os.getenv("POCGEN_HTTP_PROXY"))
    sample_timeout: float = Field(default=float(os.getenv("POCGEN_SAMPLE_TIMEOUT", "8")))
    validation_timeout: float = Field(default=float(os.getenv("POCGEN_VALIDATION_TIMEOUT", "8")))
    sample_preview_chars: int = Field(default=int(os.getenv("POCGEN_SAMPLE_PREVIEW", "2000")))
    max_iterations: int = Field(default=int(os.getenv("POCGEN_MAX_ITERS", "1")))
    stop_on_success: bool = Field(default=os.getenv("POCGEN_STOP_ON_SUCCESS", "true").lower() not in {"0", "false", "no"})
    monitor_timeout: float = Field(default=float(os.getenv("POCGEN_MONITOR_TIMEOUT", "10")))


def get_settings() -> AppSettings:
    return AppSettings()


SETTINGS = get_settings()
