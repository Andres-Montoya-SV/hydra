"""A thin command-line client for the Hydra API (Productization Phase 13c).

It only calls the documented public API, exactly as any other client
would; it is never a second way into Hydra and has no privileges of its
own. Standard library only. Run it as `python -m hydra_client --help`.
"""

from hydra_client.client import ApiError, HydraClient, TransportError

__all__ = ["ApiError", "HydraClient", "TransportError"]
