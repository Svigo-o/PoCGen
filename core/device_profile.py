"""Device profile caching for firmware targets.

Stores device-specific information (CGI paths, request format, injection method)
so that validated knowledge can be reused across same-model devices.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from PoCGen.config.config import SETTINGS


@dataclass
class DeviceProfile:
    """Cached knowledge about a firmware device target."""

    device_name: str
    ip: str
    web_server: str = ""  # e.g. shttpd, lighttpd, uhttpd, goahead
    request_format: str = ""  # "json" or "form-urlencoded"
    cgi_paths: List[str] = field(default_factory=list)  # e.g. ["/cgi-bin/cstecgi.cgi"]
    injection_method: str = ""  # e.g. "Uci_Set_Str", "sprintf+system"
    injection_delimiter: str = "`"  # backtick, $(), ;, &&
    requires_referer: bool = False
    requires_cookie: bool = False
    cookie_header: str = ""
    cves_validated: List[str] = field(default_factory=list)
    notes: str = ""

    def as_prompt_block(self) -> str:
        """Format as a prompt block for LLM context."""
        parts = [f"Device Profile: {self.device_name} ({self.ip})"]
        if self.web_server:
            parts.append(f"Web Server: {self.web_server}")
        if self.request_format:
            parts.append(f"Request Format: {self.request_format}")
        if self.cgi_paths:
            parts.append(f"CGI Paths: {', '.join(self.cgi_paths)}")
        if self.injection_method:
            parts.append(f"Injection Method: {self.injection_method}")
        if self.injection_delimiter:
            parts.append(f"Preferred Delimiter: {self.injection_delimiter}")
        if self.requires_referer:
            parts.append("Requires Referer Header: Yes")
        if self.requires_cookie:
            parts.append(f"Cookie: {self.cookie_header}")
        if self.cves_validated:
            parts.append(f"Validated CVEs: {len(self.cves_validated)}")
        if self.notes:
            parts.append(f"Notes: {self.notes}")
        return "\n".join(parts)


def _profile_dir() -> str:
    d = os.path.join(SETTINGS.output_base, "device_profiles")
    os.makedirs(d, exist_ok=True)
    return d


def _profile_path(device_name: str) -> str:
    safe_name = device_name.replace(" ", "_").replace("/", "_")
    return os.path.join(_profile_dir(), f"{safe_name}.json")


def save_profile(profile: DeviceProfile) -> str:
    """Save a device profile to disk. Returns the file path."""
    path = _profile_path(profile.device_name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(profile), f, ensure_ascii=False, indent=2)
    return path


def load_profile(device_name: str) -> Optional[DeviceProfile]:
    """Load a device profile from disk. Returns None if not found."""
    path = _profile_path(device_name)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return DeviceProfile(**data)


def list_profiles() -> List[Dict[str, str]]:
    """List all saved device profiles with basic info."""
    profiles = []
    d = _profile_dir()
    if not os.path.exists(d):
        return profiles
    for fname in os.listdir(d):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(d, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
                profiles.append({
                    "device_name": data.get("device_name", ""),
                    "ip": data.get("ip", ""),
                    "web_server": data.get("web_server", ""),
                    "cves_count": len(data.get("cves_validated", [])),
                })
            except Exception:
                continue
    return profiles


def add_cve_to_profile(device_name: str, cve_id: str) -> Optional[DeviceProfile]:
    """Add a validated CVE to an existing device profile."""
    profile = load_profile(device_name)
    if profile is None:
        return None
    if cve_id not in profile.cves_validated:
        profile.cves_validated.append(cve_id)
        save_profile(profile)
    return profile
