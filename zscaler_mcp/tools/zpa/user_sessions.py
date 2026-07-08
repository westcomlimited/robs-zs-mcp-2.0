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
Auth uses the same OAuth2 client credentials as the SDK, obtained independently
via the Zscaler OneAPI token endpoint with a 55-minute TTL cache.

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

# Simple in-process token cache {token, expires_at}
_token_cache: Dict = {"token": None, "expires_at": 0}


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
    Obtain an OAuth2 Bearer token for the ZPA portal service endpoints.

    Uses the same CLIENT_ID / CLIENT_SECRET as the SDK but calls the
    Zscaler OneAPI token endpoint directly. Token is cached for 55 minutes
    (Zscaler tokens expire at 60 minutes).

    Token endpoint: https://{ZSCALER_VANITY_DOMAIN}.zslogin.net/oauth2/v1/token
    """
    global _token_cache

    # Return cached token if still valid
    if _token_cache["token"] and time.time() < _token_cache["expires_at"]:
        return _token_cache["token"]

    # Read credentials from env (same values the SDK uses)
    client_id = os.environ.get("ZSCALER_CLIENT_ID", "").strip()
    client_secret = os.environ.get("ZSCALER_CLIENT_SECRET", "").strip()
    vanity_domain = os.environ.get("ZSCALER_VANITY_DOMAIN", "").strip()

    if not all([client_id, client_secret, vanity_domain]):
        raise ValueError(
            "ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET, and ZSCALER_VANITY_DOMAIN "
            "must all be set in your .env file."
        )

    token_url = f"https://{vanity_domain}.zslogin.net/oauth2/v1/token"

    resp = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()

    token_data = resp.json()
    token = token_data["access_token"]
    expires_in = token_data.get("expires_in", 3600)

    # Cache with 55-minute TTL regardless of actual expiry
    _token_cache["token"] = token
    _token_cache["expires_at"] = time.time() + min(expires_in - 300, 3300)

    return token


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

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - (hours * 3600 * 1000)

    url = (
        f"https://{cloud}-zpa-ras.private.zscaler.com"
        f"/api/recent-activity/customers/{customer_id}"
        f"/recentusers/from/{from_ms}/to/{now_ms}"
        f"?page={page}"
    )
    try:
        data = _portal_get(url, token)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 400:
            # RAS API returns 400 when no activity exists in the window
            return {"totalUsers": 0, "pages": 0, "users": []}
        raise

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

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - (hours * 3600 * 1000)

    url = (
        f"https://{cloud}-zpa-ras.private.zscaler.com"
        f"/api/recent-activity/customers/{customer_id}"
        f"/recentusers/from/{from_ms}/to/{now_ms}"
        f"?userId={user_id}&page=1"
    )
    return _portal_get(url, token)
