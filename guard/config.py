from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  
    import tomli as tomllib  


DEFAULT_CONFIG_PATHS = (
    Path("./guardd.toml"),
    Path("/etc/guardd/config.toml"),
    Path("/opt/guardd/config.toml"),
)


class ConfigError(Exception):
    pass


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a TOML table: {path}")

    return data


def load_config() -> tuple[dict[str, Any], Path | None]:
    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return _read_toml(path), path
    return {}, None


def deep_get(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        if key not in current:
            return default
        current = current[key]
    return current
