"""
Shopify Public App OAuth Lambda Function
=========================================
Single-file AWS Lambda that handles the Shopify OAuth 2.0 install + callback flow.
Invoked by API Gateway HTTP API (payload format version 2.0).

Environment variables required:
    SHOPIFY_API_KEY    - The app's public API key from the Shopify Partner dashboard.
    SHOPIFY_API_SECRET - The app's secret key (used for HMAC validation & token exchange).
    SCOPES             - Comma-separated OAuth scopes, e.g. "read_products,read_orders".
    REDIRECT_URI       - Fully-qualified callback URL, e.g.
                         "https://<api-id>.execute-api.<region>.amazonaws.com/oauth/callback".

IAM permissions required on the Lambda execution role:
    {
        "Effect": "Allow",
        "Action": [
            "secretsmanager:CreateSecret",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecret",
            "secretsmanager:DescribeSecret"
        ],
        "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:shopify/*"
    }
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from urllib.parse import urlencode, parse_qs, urlparse

import boto3
import requests
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
SHOPIFY_API_KEY: str = os.environ["SHOPIFY_API_KEY"]
SHOPIFY_API_SECRET: str = os.environ["SHOPIFY_API_SECRET"]
SCOPES: str = os.environ["SCOPES"]
REDIRECT_URI: str = os.environ["REDIRECT_URI"]

# Secrets Manager client — reused across warm invocations.
_sm_client = boto3.client("secretsmanager")


# ---------------------------------------------------------------------------
# HTTP response helpers
# ---------------------------------------------------------------------------

def _redirect(url: str) -> dict:
    """Return an API Gateway v2 302 redirect response."""
    return {
        "statusCode": 302,
        "headers": {"Location": url},
        "body": "",
    }


def _error(status: int, message: str) -> dict:
    """Return a JSON error response."""
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": message}),
    }


# ---------------------------------------------------------------------------
# Helper — HMAC validation
# ---------------------------------------------------------------------------

def verify_hmac(query_params: dict[str, str], secret: str) -> bool:
    """
    Validate the HMAC signature Shopify appends to the callback URL.

    Shopify signs every query-string parameter *except* ``hmac`` itself.
    The remaining key=value pairs are sorted lexicographically, joined with
    ``&``, and hashed with the app's API secret using SHA-256.

    Returns True when the computed digest matches the provided ``hmac`` value.
    """
    received_hmac = query_params.get("hmac", "")
    if not received_hmac:
        return False

    # Build the message from all params except 'hmac'.
    filtered = {k: v for k, v in query_params.items() if k != "hmac"}
    sorted_params = "&".join(f"{k}={v}" for k, v in sorted(filtered.items()))

    computed = hmac.new(
        secret.encode("utf-8"),
        sorted_params.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks.
    return hmac.compare_digest(computed, received_hmac)


# ---------------------------------------------------------------------------
# Helper — Token exchange
# ---------------------------------------------------------------------------

def exchange_token(shop: str, code: str) -> dict:
    """
    Exchange the temporary authorization code for a permanent access token
    by POSTing to Shopify's ``/admin/oauth/access_token`` endpoint.

    Returns the full JSON response which includes at minimum:
        {
            "access_token": "...",
            "scope": "..."
        }

    Raises ``RuntimeError`` on non-200 responses.
    """
    url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        "client_id": SHOPIFY_API_KEY,
        "client_secret": SHOPIFY_API_SECRET,
        "code": code,
    }

    resp = requests.post(url, json=payload, timeout=10)

    if resp.status_code != 200:
        raise RuntimeError(
            f"Token exchange failed ({resp.status_code}): {resp.text}"
        )

    return resp.json()


# ---------------------------------------------------------------------------
# Helper — Secrets Manager storage
# ---------------------------------------------------------------------------

def store_token(shop: str, access_token: str) -> None:
    """
    Persist the shop's access token in AWS Secrets Manager.

    Secret name format: ``shopify/<shop_domain>``
    (e.g. ``shopify/my-store.myshopify.com``).

    If the secret already exists it is updated; otherwise a new one is created.
    """
    secret_name = f"shopify/{shop}"
    secret_value = json.dumps({
        "shop": shop,
        "access_token": access_token,
    })

    try:
        # Try to update an existing secret first.
        _sm_client.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_value,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            # Secret doesn't exist yet — create it.
            _sm_client.create_secret(
                Name=secret_name,
                SecretString=secret_value,
            )
        else:
            raise


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def handle_install(event: dict) -> dict:
    """
    GET /install?shop=<shop>

    Generates a cryptographic nonce, builds the Shopify OAuth authorize URL,
    and returns a 302 redirect so the merchant's browser navigates to the
    Shopify consent screen.

    NOTE: The ``state`` (nonce) should ideally be persisted (e.g. DynamoDB)
    and verified in the callback to prevent CSRF.  For brevity this example
    generates but does not persist it — production code must add that check.
    """
    params = event.get("queryStringParameters") or {}
    shop = params.get("shop", "").strip()

    if not shop:
        return _error(400, "Missing required query parameter: shop")

    # Basic sanity check on the shop domain.
    if not shop.endswith(".myshopify.com"):
        return _error(400, "Invalid shop domain — must end with .myshopify.com")

    # Cryptographic nonce to guard against CSRF (see note above).
    nonce = secrets.token_hex(16)

    authorize_url = f"https://{shop}/admin/oauth/authorize?" + urlencode({
        "client_id": SHOPIFY_API_KEY,
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": nonce,
    })

    return _redirect(authorize_url)


def handle_callback(event: dict) -> dict:
    """
    GET /oauth/callback?code=...&hmac=...&shop=...&state=...&timestamp=...

    1. Validates the HMAC signature to ensure the request came from Shopify.
    2. Exchanges the authorization ``code`` for a permanent access token.
    3. Stores the token in Secrets Manager keyed by shop domain.
    4. Redirects to the Shopify admin page for the app.
    """
    params = event.get("queryStringParameters") or {}

    # --- Step 1: Validate HMAC -------------------------------------------
    if not verify_hmac(params, SHOPIFY_API_SECRET):
        return _error(403, "HMAC validation failed")

    shop = params.get("shop", "")
    code = params.get("code", "")

    if not shop or not code:
        return _error(400, "Missing required parameters: shop, code")

    # --- Step 2: Exchange code for access token --------------------------
    try:
        token_data = exchange_token(shop, code)
    except RuntimeError as exc:
        return _error(502, str(exc))

    access_token = token_data.get("access_token", "")
    if not access_token:
        return _error(502, "Shopify returned an empty access token")

    # --- Step 3: Store the token in Secrets Manager ----------------------
    try:
        store_token(shop, access_token)
    except ClientError as exc:
        return _error(500, f"Failed to store token: {exc}")

    # --- Step 4: Redirect merchant into the app inside Shopify admin -----
    redirect_url = f"https://{shop}/admin/apps/{SHOPIFY_API_KEY}"
    return _redirect(redirect_url)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

# Map (HTTP method, path) → handler.
_ROUTES: dict[tuple[str, str], callable] = {
    ("GET", "/install"): handle_install,
    ("GET", "/oauth/callback"): handle_callback,
}


def _resolve_route(event: dict) -> callable | None:
    """
    Extract method + path from an API Gateway HTTP API v2 event and look up
    the matching handler.
    """
    # HTTP API v2 payload structure.
    request_context = event.get("requestContext", {})
    http_info = request_context.get("http", {})
    method = http_info.get("method", "").upper()
    path = http_info.get("path", "")

    return _ROUTES.get((method, path))


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context) -> dict:
    """
    Main entry point invoked by AWS Lambda.

    Routes the incoming API Gateway HTTP API event to the appropriate handler
    based on the HTTP method and path.
    """
    handler = _resolve_route(event)

    if handler is None:
        return _error(404, "Not found")

    return handler(event)
