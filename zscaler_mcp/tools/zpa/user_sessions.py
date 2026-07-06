"""
ZPA User Sessions & Activity Tools
===================================
Covers ZPA reporting/session endpoints NOT exposed by the upstream
zscaler-mcp-server.  All tools are read-only.

Endpoints wrapped:
  GET /zpa/mgmtconfig/v1/admin/customers/{id}/userActivity
  GET /zpa/mgmtconfig/v1/admin/customers/{id}/userConnections
  GET /zpa/mgmtconfig/v1/admin/customers/{id}/userActivity/{userId}

These APIs are present in the ZPA platform but absent from the official
Python SDK, so we reach through to the underlying request executor directly
(same pattern used by CustomerControllerAPI in the SDK).
"""

import os
from typing import Annotated, Dict, List, Optional

from pydantic import Field
from zscaler.utils import format_url

from zscaler_mcp.client import get_zscaler_client
from zscaler_mcp.common.jmespath_utils import apply_jmespath


def _get_zpa_base(client) -> str:
    """Derive the per-customer ZPA mgmtconfig base path from the client config."""
    customer_id = (
        client.zpa._config.get("client", {}).get("customerId")
        or os.environ.get("ZSCALER_CUSTOMER_ID")
    )
    if not customer_id:
        raise ValueError(
            "ZSCALER_CUSTOMER_ID is not set. "
            "Add it to your .env file or pass customer_id explicitly."
        )
    return f"/zpa/mgmtconfig/v1/admin/customers/{customer_id}"


def _raw_get(client, path: str, query_params: Optional[Dict] = None) -> Dict:
    """Execute a raw GET against the ZPA API using the SDK's request executor."""
    req_exec = client.zpa._request_executor
    url = format_url(path)

    request, error = req_exec.create_request("GET", url, {}, {})
    if error:
        raise Exception(f"Failed to build request for {path}: {error}")

    response, error = req_exec.execute(request, dict)
    if error:
        raise Exception(f"ZPA API request failed [{path}]: {error}")

    return response.get_body()


# =============================================================================
# zpa_list_active_sessions
# =============================================================================

def zpa_list_active_sessions(
    page: Annotated[
        Optional[int],
        Field(ge=1, description="Page number for pagination (default: 1)."),
    ] = None,
    page_size: Annotated[
        Optional[int],
        Field(ge=1, le=500, description="Results per page (default: 20, max: 500)."),
    ] = None,
    query: Annotated[
        Optional[str],
        Field(description="JMESPath expression for client-side filtering/projection."),
    ] = None,
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    List currently active ZPA user sessions (user connections).

    Returns each connected user with their tunnel state, app connector,
    application segment, client IP, ZEN node, and session timestamps.
    Useful for answering 'how many users are connected to ZPA right now'
    and for per-user session debugging.

    Supports JMESPath client-side filtering via the query parameter.
    """
    client = get_zscaler_client(service=service)
    base = _get_zpa_base(client)
    path = f"{base}/userConnections"

    # Build query string manually — raw executor takes a plain URL
    params = []
    if page is not None:
        params.append(f"page={page}")
    if page_size is not None:
        params.append(f"pagesize={page_size}")
    if params:
        path = f"{path}?{'&'.join(params)}"

    result = _raw_get(client, path)

    # The API wraps results in a 'list' key with 'totalPages' metadata
    sessions = result if isinstance(result, list) else result.get("list", result)
    return apply_jmespath(sessions, query)


# =============================================================================
# zpa_get_active_session_count
# =============================================================================

def zpa_get_active_session_count(
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    Return the total number of currently active ZPA user sessions.

    Calls the same userConnections endpoint but returns only the count
    and a summary — useful for dashboards and Teams/Slack notifications
    without pulling the full session list.
    """
    client = get_zscaler_client(service=service)
    base = _get_zpa_base(client)
    result = _raw_get(client, f"{base}/userConnections?pagesize=1")

    total = result.get("totalCount") or result.get("total") or 0
    # Fall back to counting the list if the API doesn't return a totalCount
    if not total and isinstance(result.get("list"), list):
        # Fetch a larger page to get a real count
        full = _raw_get(client, f"{base}/userConnections?pagesize=500")
        session_list = full.get("list", [])
        total = full.get("totalCount") or len(session_list)

    return {
        "active_session_count": total,
        "source_endpoint": f"{base}/userConnections",
    }


# =============================================================================
# zpa_list_user_activity
# =============================================================================

def zpa_list_user_activity(
    page: Annotated[Optional[int], Field(ge=1, description="Page number.")] = None,
    page_size: Annotated[
        Optional[int], Field(ge=1, le=500, description="Results per page.")
    ] = None,
    query: Annotated[
        Optional[str],
        Field(description="JMESPath expression for client-side filtering."),
    ] = None,
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    List ZPA user activity records.

    Returns a log of recent user access events — app segment accessed,
    connector used, bytes transferred, and session duration. Use this for
    access auditing, capacity planning, and security investigations.

    Supports JMESPath client-side filtering via the query parameter.
    """
    client = get_zscaler_client(service=service)
    base = _get_zpa_base(client)
    path = f"{base}/userActivity"

    params = []
    if page is not None:
        params.append(f"page={page}")
    if page_size is not None:
        params.append(f"pagesize={page_size}")
    if params:
        path = f"{path}?{'&'.join(params)}"

    result = _raw_get(client, path)
    records = result if isinstance(result, list) else result.get("list", result)
    return apply_jmespath(records, query)


# =============================================================================
# zpa_get_user_activity
# =============================================================================

def zpa_get_user_activity(
    user_id: Annotated[
        str,
        Field(description="The ZPA user ID to retrieve activity for."),
    ],
    service: Annotated[str, Field(description="Service to use.")] = "zpa",
) -> Dict:
    """
    Get ZPA activity records for a specific user by ID.

    Returns the full activity history for a single user — which apps they
    accessed, from which connectors, and session details. Use this when
    investigating a specific user's ZPA access patterns.
    """
    if not user_id:
        raise ValueError("user_id is required")

    client = get_zscaler_client(service=service)
    base = _get_zpa_base(client)
    return _raw_get(client, f"{base}/userActivity/{user_id}")
