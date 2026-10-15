"""Verify the owned validation dashboard's HTTPS/auth boundary without a login."""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError
from install import cli

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "service-onboarding"))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def verify(installation, *, profile, region, deployment_outputs=None, read_only_operational=False):
    if read_only_operational and not deployment_outputs:
        raise ValueError("OPERATIONAL_HTTP_CHECK_REQUIRES_TERRAFORM_OUTPUTS")
    if not read_only_operational and (installation.get("status") != "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED"
            or installation.get("automatic_onboarding_enabled") is not False):
        raise ValueError("VALIDATION_ONLY_INSTALL_REQUIRED")
    account = cli("sts", "get-caller-identity", profile=profile, region=region)["Account"]
    if account != installation["account_id"]: raise ValueError("WRONG_VALIDATION_ACCOUNT")
    if deployment_outputs:
        from deployment_contract import resolve_terraform
        deployment = resolve_terraform(deployment_outputs, installation_id=installation["installation_id"], account_id=account,
                                       profile=profile, region=region, call=cli)
        if not read_only_operational and deployment.foundation_parameters.get("AutomaticOnboardingEnabled") != "false":
            raise ValueError("VALIDATION_ONLY_INSTALL_REQUIRED")
        outputs = deployment.outputs
    else:
        stack = cli("cloudformation", "describe-stacks", "--stack-name", installation["installation_id"], profile=profile, region=region)["Stacks"][0]
        tags = {row["Key"]: row["Value"] for row in stack.get("Tags", [])}
        if tags.get("InstallationId") != installation["installation_id"] or tags.get("ManagedBy") != "enterprise-security":
            raise ValueError("PLATFORM_OWNERSHIP_REQUIRED")
        outputs = {row["OutputKey"]: row["OutputValue"] for row in stack["Outputs"]}
    origin = outputs["DashboardUrl"]
    if not re.fullmatch(r"https://[a-z0-9]+\.execute-api\." + re.escape(region) + r"\.amazonaws\.com", origin):
        raise ValueError("GENERATED_HTTPS_API_REQUIRED")
    opener = build_opener(NoRedirect())
    results = []
    def call(path, method="GET"):
        headers = {"Origin": origin, "Content-Type": "application/json"}
        request = Request(origin + path, data=b"{}" if method == "POST" else None, method=method, headers=headers)
        try: response = opener.open(request, timeout=20)
        except HTTPError as error: response = error
        try: return response.status, response.headers, response.read(65536)
        finally: response.close()
    status, _, body = call("/healthz")
    if status != 200 or json.loads(body).get("ok") is not True: raise ValueError("HEALTH_NOT_READY")
    results.append({"check": "HTTPS_HEALTH", "status": 200})
    status, headers, _ = call("/")
    if status != 302 or headers.get("Location") != "/auth/login": raise ValueError("PAGE_AUTHENTICATION_REQUIRED")
    results.append({"check": "PAGE_REQUIRES_LOGIN", "status": status})
    for path, method in [("/api/session", "GET"), ("/api/review-status", "GET"), ("/api/decision", "POST"),
                         ("/api/reject", "POST"), ("/api/block-ip", "POST"), ("/api/rollback-ip", "POST")]:
        status, _, _ = call(path, method)
        if status != 401: raise ValueError("UNAUTHENTICATED_API_NOT_REJECTED")
        results.append({"check": "UNAUTHENTICATED_" + path.rsplit("/", 1)[-1].upper().replace("-", "_"), "status": status})
    status, headers, _ = call("/auth/login")
    target = urlparse(headers.get("Location", "")); parameters = parse_qs(target.query)
    cookie = headers.get("Set-Cookie", "")
    if (status != 302 or target.scheme != "https" or not target.hostname or not target.hostname.endswith(".amazoncognito.com")
            or parameters.get("response_type") != ["code"] or parameters.get("code_challenge_method") != ["S256"]
            or parameters.get("client_id") != [outputs["CognitoClientId"]]
            or parameters.get("redirect_uri") != [origin + "/auth/callback"]
            or any(not parameters.get(field) for field in ("state", "nonce", "code_challenge"))
            or not all(flag in cookie for flag in ("HttpOnly", "Secure", "SameSite=Lax"))):
        raise ValueError("COGNITO_PKCE_FLOW_NOT_READY")
    results.append({"check": "COGNITO_PKCE_REDIRECT_SECURE_COOKIE", "status": status})
    return {"status": "HTTP_BOUNDARY_PASSED", "dashboard_url": origin, "checks": results,
            "installation_mode": "READ_ONLY_OPERATIONAL" if read_only_operational else "VALIDATION_ONLY",
            "authenticated_human_login": "ADMIN_BOOTSTRAP_AND_MFA_REQUIRED", "actual_response": False,
            "cookies_tokens_and_state_saved": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-result", type=Path, help="Optional legacy receipt; Terraform outputs supply installation metadata")
    parser.add_argument("--deployment-outputs", type=Path, help="External terraform output -json file")
    parser.add_argument("--read-only-operational", action="store_true", help="Permit the owned Terraform operational installation; only anonymous HTTP requests and metadata reads")
    parser.add_argument("--profile", default="default"); parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()
    from deployment_contract import installation_result
    installation = installation_result(args.install_result, deployment_outputs=args.deployment_outputs, legacy_path=ROOT / "build/install-result.json")
    result = verify(installation, profile=args.profile, region=args.region,
                    deployment_outputs=args.deployment_outputs, read_only_operational=args.read_only_operational)
    (ROOT / "build/http-validation-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
