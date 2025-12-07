from __future__ import annotations

import os
from typing import Any, Dict

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env if present
load_dotenv()


class LLMSettings(BaseModel):
    base_url: str = Field(default=os.getenv("POCGEN_API_BASE_URL", "http://222.20.126.32:30000/v1"))
    api_key: str = Field(default=os.getenv("POCGEN_API_KEY", "DeepseekV3.1_32@C402"))
    model: str = Field(default=os.getenv("POCGEN_MODEL", "deepseek"))
    timeout_seconds: int = Field(default=int(os.getenv("POCGEN_TIMEOUT", "60")))
    # Thinking mode
    extra_body: Dict[str, Any] = Field(
        default_factory=lambda: {"chat_template_kwargs": {"thinking": True}}
    )


class AppSettings(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    save_dir: str = Field(
        default=os.getenv(
            "POCGEN_OUTPUT_DIR",
            os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "outputs")),
        )
    )
    default_vuln_type: str = Field(default=os.getenv("POCGEN_VULN_TYPE", "command_injection_http"))
    attacker_url: str = Field(default=os.getenv("POCGEN_ATTACKER_URL", "http://192.168.6.1:6666/testpoc"))


def get_settings() -> AppSettings:
    return AppSettings()


SETTINGS = get_settings()
