# Xeus Lightning - Shopify OAuth App

AWS Lambda function that implements the Shopify Public App OAuth 2.0 flow.
No web framework — just a single Lambda behind API Gateway HTTP API (v2).

## Architecture

```
Merchant Browser
      |
      v
API Gateway HTTP API (v2)
      |
      |  ANY /{proxy+}
      v
+------------------------------+
|  Lambda (lambda_handler)     |
|                              |
|  GET /install                |---> 302 redirect to Shopify consent screen
|  GET /oauth/callback         |---> HMAC check -> token exchange -> store
+------------------------------+
      |
      v
AWS Secrets Manager
  shopify/<shop-domain>
```

## Project Structure

```
.
├── app/
│   └── lambda_function.py   # Lambda handler — OAuth install + callback
├── template.yaml            # CloudFormation stack (IAM, Lambda, API GW)
└── README.md
```

## Prerequisites

- AWS CLI configured with credentials
- Python 3.10+
- A Shopify Partner account with an app created
- An S3 bucket to host the Lambda deployment zip

## Environment Variables

| Variable             | Description                                       |
|----------------------|---------------------------------------------------|
| `SHOPIFY_API_KEY`    | Public API key from the Shopify Partner dashboard  |
| `SHOPIFY_API_SECRET` | Secret key (used for HMAC validation + token exchange) |
| `SCOPES`             | Comma-separated scopes, e.g. `read_products,read_orders` |
| `REDIRECT_URI`       | Full callback URL, e.g. `https://<api-id>.execute-api.<region>.amazonaws.com/oauth/callback` |

All four are injected by CloudFormation from stack parameters.

## Deployment

### 1. Package the Lambda

The `requests` library is not included in the Lambda runtime — bundle it into the zip.

```bash
mkdir -p package
pip install requests -t package/
cp app/lambda_function.py package/
cd package && zip -r ../deploy.zip . && cd ..
```

### 2. Upload to S3

```bash
aws s3 cp deploy.zip s3://<your-lambda-code-bucket>/shopify-oauth/deploy.zip
```

### 3. Deploy the CloudFormation stack

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name shopify-oauth \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      ShopifyApiKey=<YOUR_API_KEY> \
      ShopifyApiSecret=<YOUR_API_SECRET> \
      Scopes=read_products,read_orders \
      RedirectUri=https://placeholder/oauth/callback \
      CodeS3Bucket=<your-lambda-code-bucket> \
      CodeS3Key=shopify-oauth/deploy.zip
```

### 4. Get the API base URL

```bash
aws cloudformation describe-stacks \
  --stack-name shopify-oauth \
  --query "Stacks[0].Outputs[?OutputKey=='ApiBaseUrl'].OutputValue" \
  --output text
```

This returns something like:

```
https://abc123xyz.execute-api.us-east-1.amazonaws.com
```

### 5. Update RedirectUri with the real URL

Now that you have the API Gateway URL, update the stack with the correct callback:

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name shopify-oauth \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      ShopifyApiKey=<YOUR_API_KEY> \
      ShopifyApiSecret=<YOUR_API_SECRET> \
      Scopes=read_products,read_orders \
      RedirectUri=https://abc123xyz.execute-api.us-east-1.amazonaws.com/oauth/callback \
      CodeS3Bucket=<your-lambda-code-bucket> \
      CodeS3Key=shopify-oauth/deploy.zip
```

Also set this same URL as the **Allowed redirection URL** in your Shopify Partner dashboard under **App setup**.

## Endpoints

### `GET /install?shop=<shop>`

Starts the OAuth flow. Validates the shop domain, generates a CSRF nonce,
and returns a **302 redirect** to Shopify's authorization consent screen.

Example:

```
https://abc123xyz.execute-api.us-east-1.amazonaws.com/install?shop=my-store.myshopify.com
```

### `GET /oauth/callback`

Shopify redirects here after the merchant approves. The Lambda:

1. Validates the HMAC signature (SHA-256, constant-time comparison)
2. Exchanges the temporary `code` for a permanent access token via `POST /admin/oauth/access_token`
3. Stores the token in Secrets Manager at `shopify/<shop-domain>`
4. Redirects the merchant to `https://<shop>/admin/apps/<api-key>`

## Secrets Manager

Tokens are stored as JSON under the key `shopify/<shop-domain>`:

```json
{
  "shop": "my-store.myshopify.com",
  "access_token": "shpat_xxxxxxxxxxxxxxxxxxxxx"
}
```

To retrieve a token:

```bash
aws secretsmanager get-secret-value \
  --secret-id shopify/my-store.myshopify.com \
  --query SecretString \
  --output text
```

## IAM Permissions

The Lambda execution role is provisioned by CloudFormation with two inline policies:

**CloudWatch Logs** — scoped to the function's own log group:

```json
{
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ],
  "Resource": "arn:aws:logs:<region>:<account>:log-group:/aws/lambda/<stack>-function:*"
}
```

**Secrets Manager** — scoped to the `shopify/*` namespace:

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DescribeSecret"
  ],
  "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:shopify/*"
}
```

## CloudFormation Parameters

| Parameter          | Required | Default                        | Description                          |
|--------------------|----------|--------------------------------|--------------------------------------|
| `ShopifyApiKey`    | Yes      | —                              | Shopify app public API key           |
| `ShopifyApiSecret` | Yes      | —                              | Shopify app secret (NoEcho)          |
| `Scopes`           | No       | `read_products,read_orders`    | OAuth scopes                         |
| `RedirectUri`      | Yes      | —                              | Full callback URL                    |
| `CodeS3Bucket`     | Yes      | —                              | S3 bucket with the deployment zip    |
| `CodeS3Key`        | Yes      | —                              | S3 key for the deployment zip        |

## CloudFormation Outputs

| Output             | Description                           |
|--------------------|---------------------------------------|
| `ApiBaseUrl`       | Base URL of the HTTP API              |
| `FunctionName`     | Name of the deployed Lambda function  |
| `FunctionArn`      | ARN of the Lambda function            |
| `ExecutionRoleArn` | ARN of the IAM execution role         |

## Production Considerations

- **CSRF / state validation**: The `/install` handler generates a `state` nonce but does not persist it. In production, store the nonce in DynamoDB and verify it in `/oauth/callback`.
- **Custom domain**: Attach a custom domain to the API Gateway so the callback URL doesn't change across stack recreations.
- **WAF**: Consider placing AWS WAF in front of the API to rate-limit install requests.
- **Monitoring**: Add a CloudWatch alarm on Lambda errors and 5xx responses from API Gateway.
