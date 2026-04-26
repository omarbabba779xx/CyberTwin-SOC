"""Process-wide connector registry."""

from __future__ import annotations

from typing import Any, Type

from .base import BaseConnector


_REGISTRY: dict[tuple[str, str], Type[BaseConnector]] = {}


def register(connector_cls: Type[BaseConnector]) -> Type[BaseConnector]:
    """Class decorator that adds the connector to the registry."""
    _REGISTRY[(connector_cls.kind, connector_cls.name)] = connector_cls
    return connector_cls


def get_connector(kind: str, name: str, **config: Any) -> BaseConnector:
    """Instantiate a connector by (kind, name).

    Args:
        kind:   siem | soar | edr | itsm | ti
        name:   provider name, e.g. 'splunk', 'thehive', 'mock'
        config: forwarded to the connector __init__
    """
    cls = _REGISTRY.get((kind, name))
    if cls is None:
        from .base import ConnectorError
        raise ConnectorError(
            f"No connector registered for kind={kind!r} name={name!r}. "
            f"Known: {[(k, n) for (k, n) in _REGISTRY]}"
        )
    return cls(**config)


def list_connectors() -> list[dict[str, str]]:
    """Return a list of {kind, name, status} for the dashboard."""
    out = []
    for (kind, name), cls in sorted(_REGISTRY.items()):
        out.append({
            "kind": kind,
            "name": name,
            "implemented": not getattr(cls, "_is_stub", False),
        })
    return out
