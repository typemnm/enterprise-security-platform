# Authenticated HOTL/HITL dashboard

This package runs on AWS Lambda Node.js 24 through API Gateway HTTP API v2 (`lambda.handler`, delegating to `lambda-handler.js`). `node server.js` is available for a company-managed reverse proxy or a legacy EC2 migration. Install the exact dependencies with `npm ci --omit=dev --ignore-scripts`; deploy the package files and `node_modules` together. Node.js 24 is the supported LTS major; `.node-version` records the selected release.

The foundation creates a Cognito public OAuth client, HTTPS dashboard origin, session table, and `security-admins` group. The company installer supplies its administrator email and receives the Cognito invitation. The package contains no administrator password, shared login secret, or browser-provided operator identity.

Required environment variables:

| Variable | Meaning |
| --- | --- |
| `PUBLIC_ORIGIN` | Exact HTTPS origin, including a nondefault port if applicable; no trailing slash |
| `OIDC_ISSUER` | Cognito user-pool issuer |
| `OIDC_CLIENT_ID` | Public client supporting Authorization Code + PKCE |
| `OIDC_REDIRECT_URI` | `PUBLIC_ORIGIN/auth/callback`, registered on the Cognito client |
| `SESSION_TABLE` | DynamoDB table, string partition key `session_id`, numeric TTL `expires_at` |
| `SERVICE_REGISTRY_TABLE` | Trusted registry, string partition key `service_id` |
| `COMPANY_ACCOUNT_ID` | Twelve-digit account ID allowed by this installation |
| `APPROVE_FUNCTION_NAME` | Company runtime approval Lambda ARN; its role accepts invocation from this dashboard |
| `REPORT_BUCKET` | Shared company report bucket; the foundation uses its private audit bucket |
| `AWS_REGION` | Deployment region |

`ADMIN_GROUPS` defaults to `security-admins`; `READER_GROUPS` defaults to `security-admins,security-readers`. The registry can assign `allowed_admin_groups` and `allowed_reader_groups` for individual services. A company-wide `security-admins` operator still needs an enabled registry entry with the same company account and a permitted action. A manual block additionally requires `manual_block_enabled=true` and a trusted case at `DECIDED_APPROVE`, `decision=approve`, `callback_status=SENT`, `approved_action=block_ip`, tier 2 or 3. Pending cases cannot bypass approval by using the manual block endpoint. Protected CIDRs cannot receive a new block. `DEFAULT_SERVICE_ID` is optional and reserved for an explicit migration of old flat report keys; new installations must leave it unset.

Configure Cognito logout URL `PUBLIC_ORIGIN/auth/logged-out`. Authentication checks the signature, issuer, access-token client ID, ID-token audience, token type, expiry, PKCE state, nonce, and matching subjects. The session is at most 15 minutes and at most either token's expiry. Its opaque cookie is HttpOnly, Secure, and SameSite=Lax. DynamoDB stores verified claims and short-lived login state, never OAuth access or refresh tokens. State consumption is conditional and atomic. An absent IdP or session configuration denies protected requests. `/healthz` remains public and contains no inventory or configuration details.

All state-changing requests require verified administrator role, the exact public Origin, JSON content type, and a session-bound CSRF header. Available Fetch Metadata must indicate `same-origin`. Forwarded proxy headers never establish identity or the public origin. Client `by`, `user`, `actor`, `decided_by`, and `requested_by` fields are rejected; trusted `sub` is the operator in audit and decision payloads. A reader can log out but cannot change case decisions or WAF state.

Canonical report keys are `service_id/inv-<32 hex>.md`. The key's service must match the authoritative case record and the registry. Listing uses only authorized registry service prefixes, with no whole-bucket report scan. The status RPC contract is `{operation:"status",key}` returning `ok`, `case_id`, `service_id`, `tier`, `target.source_ip`, `recommended_action`, case/decision status and callback flags. Task tokens never appear in status or browser responses. Approve/reject RPCs resume the existing case callback and pass the verified subject in the internal `user` field. No workflow is started from model-written report metadata.

`POST /api/rollback-ip` accepts exactly `{key,reason,request_id,expected_lock_token}`. It derives the IP from the case and selects `waf_ipset_arn` for IPv4 or `waf_ipv6_ipset_arn` for IPv6 from the registry. It removes only an exact `/32` or `/128`, preserves other entries and description, and returns `409` for a stale view or optimistic-lock race. A missing set or family mismatch denies the operation. CloudFront uses `us-east-1`; regional WAF uses the region in its allowlisted ARN. Completed and failed HOTL states, including `AUTO_BLOCK_PARTIAL`, may roll back a present host entry. NACL, temporary WAF, broader CIDRs, and instance isolation remain unchanged. A new detection may reapply a block.

Rollback and manual block first conditionally write an attempted audit under `decisions/<report key>.<operation>.<UUID>.json`, then conditionally complete it with its ETag. UUIDs bind the trusted actor, service, registry revision, IP, and reason (rollback also binds the view lock). If WAF succeeds but audit completion fails, the response identifies the audit gap and preserves the same request for retry. Replaying a completed rollback never deletes a newer block. Audit objects have no automatic deletion in this package; retention and bucket policies are foundation concerns.

Markdown is sanitized with an explicit element/attribute/protocol allowlist before rendering. CSP nonces permit the application's scripts while blocking stored scripts, injected event handlers, foreign images, frames, forms, and dangerous links. Responses use no-store caching, no-referrer, frame denial, and MIME sniffing protection. Identity-provider failures expose generic messages; tokens and authorization codes are not logged.

Required runtime IAM: registry `GetItem`/`Scan`; session `GetItem`/`PutItem`/conditional `DeleteItem`; exact company approval Lambda `InvokeFunction`; report prefix list/read and decision-display writes; audit-prefix `GetObject`/`PutObject`; registered company WAF IPSet `GetIPSet`/`UpdateIPSet`; KMS access for these company resources. `states:StartExecution` is not required. Legacy execution display additionally requires a configured `STATE_MACHINE_ARN`, a matching stored case execution ARN, and `states:DescribeExecution` for that workflow.

New installations perform approved IP blocks through the committed Step Functions workflow. The separate `/api/block-ip` endpoint and button are disabled by default; authenticated requests receive `405 workflow_approval_required` before a case or WAF read. Only an explicitly reviewed legacy installation can enable it with `MANUAL_IP_BLOCK_ENDPOINT_ENABLED=true`. HOTL WAF rollback remains available under its existing case, service, actor and LockToken checks.

Lambda disables synchronous `require(ESM)`. Markdown and JOSE use dynamic imports, and `html-sanitizer.js` preloads htmlparser2 for the pinned sanitize-html CommonJS module through an isolated resolver. It verifies exact package versions and entrypoint SHA256 hashes before evaluating package code; dependency upgrades require reviewing this adapter and updating those hashes. No global resolver hooks or runtime experimental flags are enabled. `npm test` exercises this Lambda restriction, real Markdown/XSS sanitization and JOSE RSA verification.

Malformed or oversized JSON is handled for every route with code-only `400 invalid_json` or `413 payload_too_large`. The final error boundary avoids Express's default error renderer/logger even when `NODE_ENV` is unset, and unexpected failures expose only a static error code. The disabled direct-block gate runs after authentication/CSRF and before body parsing.

Run `npm test` for offline RSA, OIDC/session, RBAC, CSRF, XSS, service-bound operation, audit-retry, WAF-lock, and HTTP API v2 cookie tests. These tests use local/fake clients and do not mutate AWS. `npm audit --omit=dev` checks the locked dependency graph. Live Cognito sign-in and company service registration are installation validation steps requiring that company's IdP and discovered inventory.
