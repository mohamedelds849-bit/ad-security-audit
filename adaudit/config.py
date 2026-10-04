"""Load thresholds from YAML (config/default.yaml, optionally overridden by --config)."""
from __future__ import annotations

import copy
import os

import yaml

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "config", "default.yaml")


class ConfigError(ValueError):
    pass


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _read_yaml(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)  # safe_load: never instantiate arbitrary objects
    except OSError as exc:
        raise ConfigError(f"configuration illisible: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide dans {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: la racine doit être un dictionnaire")
    return data


def load_config(path: str | None = None) -> dict:
    cfg = _read_yaml(DEFAULT_PATH)
    if path:
        cfg = _merge(cfg, _read_yaml(path))
    th = cfg.get("thresholds", {})
    for key, value in th.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ConfigError(f"thresholds.{key}: nombre positif attendu, reçu {value!r}")
    for key in ("privileged_groups", "obsolete_os", "obsolete_os_exceptions",
                "password_hint_patterns"):
        value = cfg.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{key}: liste de chaînes attendue")
    return cfg
