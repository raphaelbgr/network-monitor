"""MAC vendor/manufacturer resolution."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_lookup_instance = None
_initialized = False


def _get_lookup():  # type: ignore[no-untyped-def]
    """Lazily initialize the MAC vendor lookup database."""
    global _lookup_instance, _initialized
    if _initialized:
        return _lookup_instance
    _initialized = True
    try:
        from mac_vendor_lookup import MacLookup

        ml = MacLookup()
        try:
            ml.load_vendors()
        except Exception:
            pass
        _lookup_instance = ml
        return _lookup_instance
    except ImportError:
        logger.warning("mac-vendor-lookup not installed; vendor resolution disabled")
        return None
    except Exception as exc:
        logger.warning("Failed to initialize MAC vendor lookup: %s", exc)
        return None


def lookup_vendor(mac: str) -> str | None:
    """Resolve a MAC address to its vendor/manufacturer name.

    Returns None if the vendor is unknown or the lookup library is unavailable.
    """
    lookup = _get_lookup()
    if lookup is None:
        return None
    try:
        from mac_vendor_lookup import VendorNotFoundError
    except ImportError:
        VendorNotFoundError = Exception  # type: ignore[misc, assignment]
    try:
        result = lookup.lookup(mac)
        return result if result else None
    except VendorNotFoundError:
        return None
    except Exception:
        return None
