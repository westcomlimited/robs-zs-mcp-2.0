"""
ZPA User Sessions & Activity Tools — v2
========================================
Endpoints discovered from ZPA Admin Portal HAR capture (admin.private.zscaler.com).

Health-proxy (active sessions):
  GET https://{cloud}-zpa-health-proxy.private.zscaler.com/health/{customerId}/users
  Response: {"total": "4", "users": [...]}

Recent-activity (time-windowed):
  GET https://{cloud}-zpa-ras.private.zscaler.com/api/recent-activity/customers/{customerId}/recentusers/from/{ts}/to/{ts}
  Response: {"pages": 1, "totalUsers": 4, "users": [...]}

These are NOT mgmtconfig endpoints — they live on separate portal service hosts.
Auth is the same OAuth2 Bearer token the SDK obtains, extracted via create_request().

Required .env additions:
  ZSCALER_ZPA_CLOUD_PREFIX=us4    <- cloud/region prefix for your tenant
"""

import os
import time
from typing import Annotated, Dict, Optional

import requests
from pydantic import Field

from zscaler_mcp.client import get_zscaler_client
from zscaler_mcp.common.jmespath_utils import apply_jmespath


# =============================================================================
# Internal helpers
# =============================================================================

def _get_cloud_prefix() -> str:
    """Return the ZPA cloud prefix (e.g. 'us4') from env."""
    prefix = os.environ.get("ZSCALER_ZPA_CLOUD_PREFIX", "").strip()
    if not prefix:
        raise ValueError(
            "ZSCALER_ZPA_CLOUD_PREFIX is not set. "
            "Add it to your .env (e.g. ZSCALER_ZPA_CLOUD_PREFIX=us4)."
        )
    return prefix


def _get_customer_id(client) -> str:
    """Derive customer ID from SDK config or env."""
    customer_id = (
        client.zpa._config.get("client", {}).get("customerId")
        or os.environ.get("ZSCALER_CUSTOMER_ID")
    )
    if not customer_id:
        raise ValueError(
            "ZSCALER_CUSTOMER_ID is not set. Add it to your .env file."
        )
    return str(customer_id)


def _get_bearer_token(client) -> str:
    """
    Extract the current OAuth2 Bearer token from the ZPA SDK client.

    Strategy (in order):
    1. Intercept via create_request() -- uses the SDK's live auth flow,
       guaranteed to return a valid non-expired token.
    2. Walk common internal attribute paths across SDK versions.
    3. Fall back to ZSCALER_ZPA_BEARER_TOKEN env var (manual override).
    """
    req_exec = client.zpa._request_executor

    # Strategy 1: ask the SDK to build a lightweight request and read the header
    try:
        dummy_url = "/zpa/mgmtconfig/v1/admin/customers/0/applicationSegment"
        req, error = req_exec.create_request("GET", dummy_url, {}, {})
        if not error and req is not None:
            headers = getattr(req, "headers", {}) or {}
            for key, val in headers.items():
                if key.lower() == "authorization" and val.startswith("Bearer "):
                    return val[len("Bearer "):]
    except Exception:
        pass

    # Strategy 2: common internal attribute paths across SDK versions
    candidates = [
        ("_access_token",),
        ("_token",),
        ("_http_client", "_access_token"),
        ("_http_client", "access_token"),
        ("_http_client", "_token"),
        ("_auth", "_access_token"),
    ]
    for path in candidates:
        try:
            obj = req_exec
            for attr in path:
                obj = getattr(obj, attr)
            if obj and isinstance(obj, str) and obj.startswith("ey"):
                return obj
        except AttributeError:
            continue

    # Strategy 3: manual env var fallback
    manual = os.environ.get("ZSCALER_ZPA_BEARER_TOKEN", "").strip()
    if manual:
        return manual

    raise RuntimeError(
        "Could not extract Bearer token from ZPA SDK. "
        "Set ZSCALER_ZPA_BEARER_TOKEN in your .env as a fallback, "
        "or open a GitHub issue with your SDK version."
    )


def _portal_get(url: str, token: str) -> Dict:
    """Authenticated GET against a ZPA portal service endpoint."""
    resp = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        },
        timeout=15,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()


# =============================================================================
# zpa_get_active_session_count
# =============================================================================

def zpa_get_active_session_count(
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    Return the total number of currently active ZPA user sessions.

    Uses the ZPA health-proxy API (us4-zpa-health-proxy.private.zscaler.com)
    discovered from portal HAR capture. Lightweight -- returns a single integer
    count. Use this for dashboards, Teams/Slack notifications, or any time you
    only need a count rather than the full session list (read-only).

    Requires ZSCALER_ZPA_CLOUD_PREFIX in .env (e.g. us4).
    """
    client = get_zscaler_client(service=service)
    token = _get_bearer_token(client)
    cloud = _get_cloud_prefix()
    customer_id = _get_customer_id(client)

    url = (
        f"https://{cloud}-zpa-health-proxy.private.zscaler.com"
        f"/health/{customer_id}/users"
        f"?scopeId=0&page=1&pagesize=1"
    )
    data = _portal_get(url, token)

    return {
        "active_session_count": int(data.get("total", 0)),
        "source_endpoint": url,
    }


# =============================================================================
# zpa_list_active_sessions
# =============================================================================

def zpa_list_active_sessions(
    page: Annotated[
        Optional[int],
        Field(ge=1, description="Page number (default: 1)."),
    ] = 1,
    page_size: Annotated[
        Optional[int],
        Field(ge=1, le=500, description="Results per page (default: 30, max: 500)."),
    ] = 30,
    query: Annotated[
        Optional[str],
        Field(description="JMESPath expression for client-side filtering/projection."),
    ] = None,
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    List currently active ZPA user sessions via the health-proxy API.

    Returns each connected user with tunnel state, app connector, application
    segment, client IP, ZEN node, and session timestamps. Use this to see who
    is connected to ZPA right now.

    Requires ZSCALER_ZPA_CLOUD_PREFIX in .env (e.g. us4).
    Supports JMESPath client-side filtering via the query parameter (read-only).
    """
    client = get_zscaler_client(service=service)
    token = _get_bearer_token(client)
    cloud = _get_cloud_prefix()
    customer_id = _get_customer_id(client)

    url = (
        f"https://{cloud}-zpa-health-proxy.private.zscaler.com"
        f"/health/{customer_id}/users"
        f"?scopeId=0&page={page}&pagesize={page_size}"
    )
    data = _portal_get(url, token)

    sessions = data.get("users", data)
    total = data.get("total", None)

    result = {"total": int(total) if total is not None else None, "users": sessions}
    return apply_jmespath(result, query)


# =============================================================================
# zpa_list_user_activity
# =============================================================================

def zpa_list_user_activity(
    hours: Annotated[
        int,
        Field(ge=1, le=24, description="Look-back window in hours (default: 1)."),
    ] = 1,
    page: Annotated[
        Optional[int],
        Field(ge=1, description="Page number (default: 1)."),
    ] = 1,
    query: Annotated[
        Optional[str],
        Field(description="JMESPath expression for client-side filtering."),
    ] = None,
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    List recent ZPA user activity via the recent-activity API.

    Returns users who connected within the specified look-back window (1-24h).
    Use for access auditing, capacity planning, and security investigations.

    Requires ZSCALER_ZPA_CLOUD_PREFIX in .env (e.g. us4).
    Supports JMESPath client-side filtering via the query parameter (read-only).
    """
    client = get_zscaler_client(service=service)
    token = _get_bearer_token(client)
    cloud = _get_cloud_prefix()
    customer_id = _get_customer_id(client)

    now = int(time.time())
    from_ts = now - (hours * 3600)

    url = (
        f"https://{cloud}-zpa-ras.private.zscaler.com"
        f"/api/recent-activity/customers/{customer_id}"
        f"/recentusers/from/{from_ts}/to/{now}"
        f"?scopeId=0&page={page}"
    )
    data = _portal_get(url, token)

    records = data.get("users", data)
    return apply_jmespath(records, query)


# =============================================================================
# zpa_get_user_activity
# =============================================================================

def zpa_get_user_activity(
    user_id: Annotated[
        str,
        Field(description="The ZPA user ID to retrieve activity for."),
    ],
    hours: Annotated[
        int,
        Field(ge=1, le=24, description="Look-back window in hours (default: 24)."),
    ] = 24,
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    Get ZPA activity records for a specific user by ID.

    Returns the full activity history for a single user over the specified
    look-back window. Use when investigating a specific user's ZPA access
    patterns (read-only).

    Requires ZSCALER_ZPA_CLOUD_PREFIX in .env (e.g. us4).
    """
    if not user_id:
        raise ValueError("user_id is required")

    client = get_zscaler_client(service=service)
    token = _get_bearer_token(client)
    cloud = _get_cloud_prefix()
    customer_id = _get_customer_id(client)

    now = int(time.time())
    from_ts = now - (hours * 3600)

    url = (
        f"https://{cloud}-zpa-ras.private.zscaler.com"
        f"/api/recent-activity/customers/{customer_id}"
        f"/recentusers/from/{from_ts}/to/{now}"
        f"?scopeId=0&userId={user_id}&page=1"
    )
    return _portal_get(url, token)
