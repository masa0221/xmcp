import asyncio
import copy
import json
import logging
import os
import time

import httpx
import requests
from fastmcp import FastMCP
from pathlib import Path

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}

LOGGER = logging.getLogger("xmcp.x_api")
AUTH_LOGGER = logging.getLogger("xmcp.oauth2")

OAUTH2_TOKEN_URL = "https://api.x.com/2/oauth2/token"


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(key: str) -> set[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return set()
    return {item.strip() for item in raw.split(",") if item.strip()}


def should_join_query_param(param: dict) -> bool:
    if param.get("in") != "query":
        return False
    schema = param.get("schema", {})
    if schema.get("type") != "array":
        return False
    return param.get("explode") is False


def collect_comma_params(spec: dict) -> set[str]:
    comma_params: set[str] = set()
    components = spec.get("components", {}).get("parameters", {})
    for param in components.values():
        if isinstance(param, dict) and should_join_query_param(param):
            name = param.get("name")
            if isinstance(name, str):
                comma_params.add(name)

    for item in spec.get("paths", {}).values():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict) or "$ref" in param:
                    continue
                if should_join_query_param(param):
                    name = param.get("name")
                    if isinstance(name, str):
                        comma_params.add(name)

    return comma_params


def load_openapi_spec() -> dict:
    url = "https://api.twitter.com/2/openapi.json"
    LOGGER.info("Fetching OpenAPI spec from %s", url)
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def load_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(env_path, override=True)


def setup_logging() -> bool:
    debug_enabled = is_truthy(os.getenv("X_API_DEBUG", "1"))
    if debug_enabled:
        logging.basicConfig(level=logging.INFO)
        LOGGER.setLevel(logging.INFO)
    return debug_enabled


def should_exclude_operation(path: str, operation: dict) -> bool:
    if "/webhooks" in path or "/stream" in path:
        return True

    tags = [tag.lower() for tag in operation.get("tags", []) if isinstance(tag, str)]
    if "stream" in tags or "webhooks" in tags:
        return True

    if operation.get("x-twitter-streaming") is True:
        return True

    return False


def filter_openapi_spec(spec: dict) -> dict:
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths", {})
    new_paths = {}
    allow_tags = {tag.lower() for tag in parse_csv_env("X_API_TOOL_TAGS")}
    allow_ops = parse_csv_env("X_API_TOOL_ALLOWLIST")
    deny_ops = parse_csv_env("X_API_TOOL_DENYLIST")

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue

        new_item = {}
        for key, value in item.items():
            if key.lower() in HTTP_METHODS:
                if should_exclude_operation(path, value):
                    continue
                operation_id = value.get("operationId")
                operation_tags = [
                    tag.lower()
                    for tag in value.get("tags", [])
                    if isinstance(tag, str)
                ]
                if allow_tags and not (set(operation_tags) & allow_tags):
                    continue
                if allow_ops and operation_id not in allow_ops:
                    continue
                if deny_ops and operation_id in deny_ops:
                    continue
                new_item[key] = value
            else:
                new_item[key] = value

        if any(method.lower() in HTTP_METHODS for method in new_item.keys()):
            new_paths[path] = new_item

    filtered["paths"] = new_paths
    return filtered


def print_tool_list(spec: dict) -> None:
    tools: list[str] = []
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_id = operation.get("operationId")
            if op_id:
                tools.append(op_id)
            else:
                tools.append(f"{method.upper()} {path}")

    tools.sort()
    print(f"Loaded {len(tools)} tools from OpenAPI:")
    for tool in tools:
        print(f"- {tool}")


class OAuth2TokenManager:
    """Manages OAuth2 access tokens with automatic refresh."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        token_file: str | None = None,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token = ""
        self._refresh_token = refresh_token
        self._expires_at = 0.0
        self._token_file = token_file
        self._lock = asyncio.Lock()

    async def get_access_token(self) -> str:
        if self._access_token and time.time() < self._expires_at - 60:
            return self._access_token
        async with self._lock:
            if self._access_token and time.time() < self._expires_at - 60:
                return self._access_token
            await self._refresh()
            return self._access_token

    async def _refresh(self) -> None:
        AUTH_LOGGER.info("Refreshing OAuth2 access token...")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OAUTH2_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh_token,
                    "client_id": self._client_id,
                },
                auth=(self._client_id, self._client_secret),
            )
            if response.status_code != 200:
                body = response.text
                raise RuntimeError(
                    f"OAuth2 token refresh failed ({response.status_code}): {body}"
                )
            data = response.json()

        self._access_token = data["access_token"]
        self._refresh_token = data["refresh_token"]
        self._expires_at = time.time() + data.get("expires_in", 7200)
        AUTH_LOGGER.info(
            "OAuth2 token refreshed, expires in %ds", data.get("expires_in", 7200)
        )

        if self._token_file:
            token_path = Path(self._token_file)
            token_path.write_text(
                json.dumps({"refresh_token": self._refresh_token}), encoding="utf-8"
            )
            AUTH_LOGGER.info("Saved new refresh token to %s", self._token_file)


def build_token_manager() -> OAuth2TokenManager:
    client_id = os.getenv("X_CLIENT_ID", "").strip()
    client_secret = os.getenv("X_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise RuntimeError("Missing X_CLIENT_ID or X_CLIENT_SECRET.")

    token_file = os.getenv("X_TOKEN_FILE", "").strip() or None

    refresh_token = ""
    if token_file:
        token_path = Path(token_file)
        if token_path.exists():
            try:
                data = json.loads(token_path.read_text(encoding="utf-8"))
                refresh_token = data.get("refresh_token", "")
                if refresh_token:
                    AUTH_LOGGER.info("Loaded refresh token from %s", token_file)
            except (json.JSONDecodeError, OSError) as e:
                AUTH_LOGGER.warning("Failed to read token file %s: %s", token_file, e)

    if not refresh_token:
        refresh_token = os.getenv("X_REFRESH_TOKEN", "").strip()

    if not refresh_token:
        raise RuntimeError(
            "No refresh token found. Set X_REFRESH_TOKEN in .env or provide X_TOKEN_FILE.\n"
            "To obtain a refresh token, run: python generate_token.py"
        )

    return OAuth2TokenManager(
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        token_file=token_file,
    )


def create_mcp() -> FastMCP:
    load_env()
    debug_enabled = setup_logging()
    parser_flag = os.getenv("FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER")
    if parser_flag is not None:
        os.environ["FASTMCP_EXPERIMENTAL_ENABLE_NEW_OPENAPI_PARSER"] = parser_flag

    base_url = os.getenv("X_API_BASE_URL", "https://api.x.com")
    timeout = float(os.getenv("X_API_TIMEOUT", "30"))

    token_manager = build_token_manager()

    spec = load_openapi_spec()
    filtered_spec = filter_openapi_spec(spec)
    comma_params = collect_comma_params(filtered_spec)
    print_tool_list(filtered_spec)

    async def normalize_query_params(request: httpx.Request) -> None:
        if not comma_params:
            return
        params = list(request.url.params.multi_items())
        grouped: dict[str, list[str]] = {}
        ordered: list[str] = []
        normalized: list[tuple[str, str]] = []

        for key, value in params:
            if key in comma_params:
                if key not in grouped:
                    ordered.append(key)
                grouped.setdefault(key, []).append(value)
            else:
                normalized.append((key, value))

        if not grouped:
            return

        for key in ordered:
            values: list[str] = []
            for raw in grouped[key]:
                for part in raw.split(","):
                    part = part.strip()
                    if part and part not in values:
                        values.append(part)
            if values:
                normalized.append((key, ",".join(values)))

        request.url = request.url.copy_with(params=normalized)

    b3_flags = os.getenv("X_B3_FLAGS", "1")

    async def add_bearer_token(request: httpx.Request) -> None:
        request.headers["X-B3-Flags"] = b3_flags
        access_token = await token_manager.get_access_token()
        request.headers["Authorization"] = f"Bearer {access_token}"

    async def log_request(request: httpx.Request) -> None:
        if not debug_enabled:
            return
        LOGGER.info("X API request %s %s", request.method, request.url)

    async def log_response(response: httpx.Response) -> None:
        if not debug_enabled:
            return
        LOGGER.info(
            "X API response %s %s -> %s",
            response.request.method,
            response.request.url,
            response.status_code,
        )
        if response.status_code >= 400:
            transaction_id = response.headers.get("x-transaction-id")
            if transaction_id:
                LOGGER.warning("X API x-transaction-id: %s", transaction_id)
            body = await response.aread()
            text = body.decode("utf-8", errors="replace")
            if len(text) > 1000:
                text = text[:1000] + "...<truncated>"
            LOGGER.warning("X API error body: %s", text)

    client = httpx.AsyncClient(
        base_url=base_url,
        headers={},
        timeout=timeout,
        event_hooks={
            "request": [normalize_query_params, add_bearer_token, log_request],
            "response": [log_response],
        },
    )
    return FastMCP.from_openapi(
        openapi_spec=filtered_spec,
        client=client,
        name="X API MCP",
    )


def main() -> None:
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8000"))
    transport = os.getenv("MCP_TRANSPORT", "http")
    if transport not in ("http", "sse", "stdio"):
        raise RuntimeError(
            f"Unsupported MCP_TRANSPORT={transport!r}. Use 'http', 'sse', or 'stdio'."
        )
    mcp = create_mcp()
    mcp.run(transport=transport, host=host, port=port)


if __name__ == "__main__":
    main()
