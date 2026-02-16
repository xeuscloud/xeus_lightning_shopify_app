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
            "secretsmanager:DescribeSecret",
            "secretsmanager:DeleteSecret"
        ],
        "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:shopify/*"
    }
"""

from __future__ import annotations

import base64
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

def verify_shopify_webhook(headers: dict, raw_body: str) -> bool:
    """
    Verify Shopify webhook HMAC signature.

    Args:
        headers: Request headers (case-insensitive lookup)
        raw_body: Raw request body string (before JSON parsing)

    Returns:
        True if signature is valid, False otherwise.
    """
    # Case-insensitive header lookup
    hmac_header = None
    for key, value in headers.items():
        if key.lower() == "x-shopify-hmac-sha256":
            hmac_header = value
            break

    if not hmac_header:
        print("[Webhook] Missing X-Shopify-Hmac-Sha256 header")
        return False

    # Compute HMAC-SHA256 and base64 encode
    computed = base64.b64encode(
        hmac.new(
            SHOPIFY_API_SECRET.encode("utf-8"),
            raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body,
            hashlib.sha256
        ).digest()
    ).decode("utf-8")

    # Constant-time comparison
    is_valid = hmac.compare_digest(computed, hmac_header)

    if not is_valid:
        print("[Webhook] HMAC verification failed")

    return is_valid


def _get_raw_body(event: dict) -> str:
    """
    Extract raw request body from API Gateway event.

    Handles base64-encoded bodies when isBase64Encoded is True.
    """
    body = event.get("body", "") or ""
    if event.get("isBase64Encoded", False) and body:
        body = base64.b64decode(body).decode("utf-8")
    return body


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

    Secret name format: ``shopify/<store_name>``
    (e.g. ``shopify/my-store`` for shop ``my-store.myshopify.com``).

    If the secret already exists it is updated; otherwise a new one is created.
    """
    # Strip .myshopify.com suffix for cleaner secret names.
    store_name = shop.removesuffix(".myshopify.com")
    secret_name = f"shopify/{store_name}"
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

    NOTE: Compliance webhooks (customers/data_request, customers/redact,
    shop/redact) are now registered via shopify.app.toml and deployed
    through Shopify CLI — no longer registered here.
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
# Webhook handlers (GDPR compliance)
# ---------------------------------------------------------------------------

def _handle_compliance_webhook(event: dict, topic: str) -> dict:
    """
    Generic handler for all compliance webhooks.

    1. Extract raw body BEFORE any parsing
    2. Verify HMAC on the raw body
    3. Return 200 immediately
    4. Log and process AFTER verification
    """
    headers = event.get("headers", {})
    raw_body = _get_raw_body(event)

    if not verify_shopify_webhook(headers, raw_body):
        return _error(401, "Unauthorized")

    # Parse AFTER HMAC verification
    try:
        payload = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        payload = {}

    shop_domain = payload.get("shop_domain", "unknown")
    print(f"[GDPR] {topic} - shop: {shop_domain}")

    # shop/redact: clean up stored credentials
    if topic == "shop/redact" and payload.get("shop_domain"):
        try:
            store_name = payload["shop_domain"].removesuffix(".myshopify.com")
            _sm_client.delete_secret(
                SecretId=f"shopify/{store_name}",
                ForceDeleteWithoutRecovery=True,
            )
            print(f"[GDPR] Deleted secret: shopify/{store_name}")
        except ClientError as exc:
            print(f"[GDPR] Could not delete secret: {exc}")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"success": True}),
    }


def handle_webhook_customers_data_request(event: dict) -> dict:
    """POST /webhooks/customers/data_request"""
    return _handle_compliance_webhook(event, "customers/data_request")


def handle_webhook_customers_redact(event: dict) -> dict:
    """POST /webhooks/customers/redact"""
    return _handle_compliance_webhook(event, "customers/redact")


def handle_webhook_shop_redact(event: dict) -> dict:
    """POST /webhooks/shop/redact"""
    return _handle_compliance_webhook(event, "shop/redact")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

# Map (HTTP method, path) → handler.
_ROUTES: dict[tuple[str, str], callable] = {
    ("GET", "/install"): handle_install,
    ("GET", "/oauth/callback"): handle_callback,
    # Compliance webhooks — paths match Shopify topic format
    ("POST", "/webhooks/customers/data_request"): handle_webhook_customers_data_request,
    ("POST", "/webhooks/customers/redact"): handle_webhook_customers_redact,
    ("POST", "/webhooks/shop/redact"): handle_webhook_shop_redact,
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
