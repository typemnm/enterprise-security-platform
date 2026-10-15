"""Install an unknown-service AWS security control plane; --plan makes no AWS calls.

Only --apply deploys resources. Workload ARNs and arbitrary response targets are
never installation inputs. The account's eligible resources are discovered by
the installed backend after guarded platform wiring.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import quote
from urllib.request import urlopen
import zipfile

ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / "build/release"
spec = importlib.util.spec_from_file_location("enterprise_onboard", ROOT / "service-onboarding/onboard.py")
onboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(onboard)
_sdk_spec = importlib.util.spec_from_file_location("installer_sdk_packaging", ROOT / "sdk_packaging.py")
sdk_packaging = importlib.util.module_from_spec(_sdk_spec)
_sdk_spec.loader.exec_module(sdk_packaging)
_node_spec = importlib.util.spec_from_file_location("installer_node_packaging", ROOT / "node_packaging.py")
node_packaging = importlib.util.module_from_spec(_node_spec)
_node_spec.loader.exec_module(node_packaging)


class InstallError(RuntimeError):
    pass


class AwsError(InstallError):
    def __init__(self, operation, code):
        self.code = code
        super().__init__(f"{operation} failed ({code}); inspect the company AWS operation logs")


def cli(*arguments, profile, region):
    result = subprocess.run(["aws", *map(str, arguments), "--profile", profile, "--region", region,
                             "--output", "json", "--no-cli-pager"], capture_output=True)
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace")
        match = re.search(r"\(([^)]+)\) when calling", message)
        code = match.group(1) if match and re.fullmatch(r"[A-Za-z0-9]+", match.group(1)) else "AWS_OPERATION_ERROR"
        raise AwsError(" ".join(arguments[:2]), code)
    for encoding in ["utf-8", "cp949"]:
        try:
            return json.loads((result.stdout or b"{}").decode(encoding))
        except (UnicodeDecodeError, ValueError):
            pass
    raise InstallError("AWS_RESPONSE_DECODE_FAILED")


def sha(path):
    raw = hashlib.sha256(path.read_bytes()).digest()
    return raw.hex(), base64.b64encode(raw).decode()


def environment_budget(values):
    # Use encoded JSON size, which is stricter than just summing key/value bytes.
    if len(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()) > 4096:
        raise InstallError("LAMBDA_ENVIRONMENT_BUDGET_EXCEEDED; reduce discovery regions or exclusions")


def stack_contract_ready(snapshot, template, values):
    """Stack events may reach COMPLETE before DescribeStacks outputs converge."""
    if snapshot.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
        return False
    outputs = {item["OutputKey"]: item.get("OutputValue") for item in snapshot.get("Outputs", [])}
    required = {key for key, definition in template.get("Outputs", {}).items() if not definition.get("Condition")}
    if any(not isinstance(outputs.get(key), str) or not outputs[key] for key in required):
        return False
    parameters = {item["ParameterKey"]: item.get("ParameterValue") for item in snapshot.get("Parameters", [])}
    return all(parameters.get(key) == str(value) for key, value in values.items())


def safe_permission_refresh(change, current_template, original_template, resource_changes):
    """Allow only unchanged grants with proven stable ARN/name dependencies."""
    if (change.get("ResourceType") != "AWS::Lambda::Permission" or change.get("Action") != "Modify"
            or change.get("Replacement") != "Conditional"):
        return False
    logical = change.get("LogicalResourceId")
    current = current_template.get("Resources", {}).get(logical, {})
    original = original_template.get("Resources", {}).get(logical, {})
    if (current.get("Type") != "AWS::Lambda::Permission" or original.get("Type") != current.get("Type")
            or current.get("Properties") != original.get("Properties") or current.get("Condition") != original.get("Condition")):
        return False
    arn_invariant_fields = {
        "AWS::Events::Rule": {"Targets", "State"},
        "AWS::Lambda::Function": {"Code", "Environment", "LoggingConfig", "Runtime", "Handler", "Layers",
                                 "MemorySize", "Timeout", "TracingConfig", "Architectures", "EphemeralStorage", "ReservedConcurrentExecutions", "Description"},
        "AWS::Lambda::Alias": {"FunctionVersion", "RoutingConfig", "Description"},
    }
    details = change.get("Details", [])
    if not details:
        return False
    for detail in details:
        target = detail.get("Target", {})
        if (detail.get("Evaluation") != "Dynamic" or target.get("Attribute") != "Properties"
                or target.get("Name") not in {"SourceArn", "FunctionName"}
                or detail.get("ChangeSource") not in {"ResourceAttribute", "ResourceReference"}):
            return False
        cause = detail.get("CausingEntity", "")
        if not isinstance(cause, str):
            return False
        parent_id, separator, attribute = cause.partition(".")
        parent_change = resource_changes.get(parent_id, {})
        parent = current_template.get("Resources", {}).get(parent_id, {})
        old_parent = original_template.get("Resources", {}).get(parent_id, {})
        kind = parent.get("Type")
        fields = arn_invariant_fields.get(kind)
        if (not fields or old_parent.get("Type") != kind or parent.get("Condition") != old_parent.get("Condition")
                or parent_change.get("Action") != "Modify" or parent_change.get("Replacement") != "False"):
            return False
        if detail["ChangeSource"] == "ResourceAttribute":
            if not separator or attribute not in ({"Arn", "AliasArn"} if kind == "AWS::Lambda::Alias" else {"Arn"}):
                return False
        elif separator or (target["Name"] == "SourceArn" and kind != "AWS::Lambda::Alias"):
            # Function Ref is a stable name; Alias Ref is a stable qualified ARN.
            # An Event Rule Ref is a name and cannot establish SourceArn safety.
            return False
        props, old_props = parent.get("Properties", {}), old_parent.get("Properties", {})
        changed = {key for key in props.keys() | old_props.keys() if props.get(key) != old_props.get(key)}
        if not changed <= fields:
            return False
        parent_details = parent_change.get("Details", [])
        if not parent_details and not changed:
            return False  # Insufficient evidence about the dependent change.
        if any(row.get("Target", {}).get("Attribute") != "Properties" or row.get("Target", {}).get("Name") not in fields for row in parent_details):
            return False
    return True


def safe_event_source_refresh(change, current_template, original_template, resource_changes):
    """Accept only the unchanged mapping's dynamically reevaluated SQS ARN."""
    if (change.get("ResourceType") != "AWS::Lambda::EventSourceMapping" or change.get("Action") != "Modify"
            or change.get("Replacement") != "Conditional"):
        return False
    logical = change.get("LogicalResourceId")
    current = current_template.get("Resources", {}).get(logical, {})
    original = original_template.get("Resources", {}).get(logical, {})
    if (current.get("Type") != "AWS::Lambda::EventSourceMapping" or original.get("Type") != current.get("Type")
            or current.get("Properties") != original.get("Properties") or current.get("Condition") != original.get("Condition")):
        return False
    details = change.get("Details", [])
    if not details:
        return False
    mutable = {"KmsMasterKeyId", "SqsManagedSseEnabled", "MaximumMessageSize"}

    def queue_change(queue_id, allow_redrive_dependency):
        parent_change = resource_changes.get(queue_id, {})
        queue = current_template.get("Resources", {}).get(queue_id, {})
        old_queue = original_template.get("Resources", {}).get(queue_id, {})
        if (queue.get("Type") != "AWS::SQS::Queue" or old_queue.get("Type") != queue.get("Type")
                or queue.get("Condition") != old_queue.get("Condition") or parent_change.get("Action") != "Modify"
                or parent_change.get("Replacement") != "False"):
            return False
        props, old_props = queue.get("Properties", {}), old_queue.get("Properties", {})
        changed = {key for key in props.keys() | old_props.keys() if props.get(key) != old_props.get(key)}
        parent_details = parent_change.get("Details", [])
        if not changed <= mutable or not parent_details:
            return False
        for row in parent_details:
            field = row.get("Target", {})
            if field.get("Attribute") != "Properties" or field.get("RequiresRecreation") not in {None, "Never"}:
                return False
            if field.get("Name") in mutable:
                continue
            # A DLQ encryption update can reevaluate the unchanged redrive ARN.
            # Accept this one dependency only after independently proving the
            # child queue identity and all non-recreating encryption changes.
            cause = row.get("CausingEntity", "")
            redrive = props.get("RedrivePolicy")
            if (not allow_redrive_dependency or field.get("Name") != "RedrivePolicy" or field.get("RequiresRecreation") != "Never"
                    or row.get("Evaluation") != "Dynamic" or row.get("ChangeSource") != "ResourceAttribute"
                    or not isinstance(cause, str) or not cause.endswith(".Arn") or not isinstance(redrive, dict)
                    or redrive != old_props.get("RedrivePolicy")):
                return False
            child_id = cause[:-4]
            if (child_id == queue_id or redrive.get("deadLetterTargetArn") != {"Fn::GetAtt": [child_id, "Arn"]}
                    or not queue_change(child_id, False)):
                return False
        return True

    for detail in details:
        target = detail.get("Target", {})
        cause = detail.get("CausingEntity", "")
        if (detail.get("Evaluation") != "Dynamic" or detail.get("ChangeSource") != "ResourceAttribute"
                or target.get("Attribute") != "Properties" or target.get("Name") != "EventSourceArn"
                or not isinstance(cause, str) or not cause.endswith(".Arn")):
            return False
        queue_id = cause[:-4]
        if current["Properties"].get("EventSourceArn") != {"Fn::GetAtt": [queue_id, "Arn"]}:
            return False
        if not queue_change(queue_id, True):
            return False
    return True


def verified_release():
    manifest_path = RELEASE / "manifest.json"
    if not manifest_path.is_file():
        raise InstallError("Run build_release.py --build before deployment")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("validation") != "passed" or manifest.get("account_neutral") is not True or manifest.get("contains_workload") is not False:
        raise InstallError("RELEASE_VALIDATION_REQUIRED")
    for name, metadata in manifest.get("artifacts", {}).items():
        if name not in {"runtime.zip", "dashboard.zip"} or sha(RELEASE / name)[0] != metadata["sha256"]:
            raise InstallError("ARTIFACT_HASH_MISMATCH")
    if set(manifest.get("artifacts", {})) != {"runtime.zip", "dashboard.zip"}:
        raise InstallError("MISSING_RELEASE_ARTIFACT")
    for name, metadata in manifest.get("templates", {}).items():
        if Path(name).name != name or sha(ROOT / "infrastructure" / name)[0] != metadata["sha256"]:
            raise InstallError("TEMPLATE_HASH_MISMATCH")
    for name, digest in manifest.get("source_files", {}).items():
        path = (ROOT / name).resolve()
        if ROOT not in path.parents or sha(path)[0] != digest:
            raise InstallError("SOURCE_CHANGED_REBUILD_REQUIRED")
    try:
        sdk_packaging.verify_manifest(ROOT, RELEASE / "runtime.zip", manifest.get("runtime_sdk", {}))
    except (ValueError, KeyError, TypeError, AttributeError, OSError, zipfile.BadZipFile):
        raise InstallError("RUNTIME_SDK_VALIDATION_REQUIRED") from None
    try:
        node_packaging.verify_manifest(ROOT, RELEASE / "dashboard.zip", manifest.get("node_dependencies", {}))
    except (ValueError, KeyError, TypeError, AttributeError, OSError, zipfile.BadZipFile):
        raise InstallError("NODE_DEPENDENCY_VALIDATION_REQUIRED") from None
    return manifest


def installation_plan(config, args, manifest=None):
    regions = sorted(set(config["discovery"]["regions"]) | {args.region, "us-east-1"})
    alarm_names = ",".join(config["installation_id"] + "-" + region + "-log-ingress-" + suffix
        for region in regions for suffix in ["errors", "async-dropped", "destination-failures", "dlq-depth"])
    if len(alarm_names.encode()) > 4096:
        raise InstallError("INGRESS_ALARM_PARAMETER_BUDGET_EXCEEDED; reduce discovery regions")
    return {"status": "PLAN", "installation_id": config["installation_id"], "account": config.get("account_id", "FROM_STS_AT_APPLY"),
            "control_plane_region": args.region, "artifact_and_ingress_regions": regions,
            "ingress_alarm_names": alarm_names,
            "discovery_scope": config["discovery"]["scope"], "response_mode": config["response_mode"],
            "default_dry_run": not args.enable_enforcement, "automatic_onboarding_after_verification": not getattr(args, "validation_only", False),
            "validation_only": getattr(args, "validation_only", False),
            "workloads_created": False, "business_target_arn_required": False,
            "cognito_mfa": "ON", "dashboard_origin": config.get("dashboard_origin", "GENERATED_HTTPS_HTTP_API"),
            "slack_enabled": bool(args.slack_secret_arn and args.slack_channel_id), "admin_invitation": bool(args.admin_email),
            "release_id": manifest.get("release_id") if manifest else "BUILD_REQUIRED_BEFORE_APPLY",
            "phases": ["verify STS account and release", "private versioned regional artifacts", "foundation automatic OFF",
                       "regional log ingress", "governance", "wire approval and ingress", "verify OAuth and code hashes",
                       *( ["keep automatic onboarding OFF", "read-only discover; no WAF reconciliation"] if getattr(args, "validation_only", False)
                          else ["enable automatic onboarding", "discover and reconcile supported resources"] )],
            "review_boundaries": ["shared ACL ownership", "Firewall Manager policy", "WAF Classic", "existing logging adapter",
                                  "non-supported direct WAF resources", "CloudFront globally constrained to us-east-1"]}


class Installer:
    def __init__(self, config, args, manifest, call=cli):
        self.config, self.args, self.manifest, self.call = config, args, manifest, call
        identity = self.aws("sts", "get-caller-identity")
        self.account = identity["Account"]
        if not re.fullmatch(r"[0-9]{12}", self.account) or not identity.get("Arn", "").startswith("arn:aws:"):
            raise InstallError("UNSUPPORTED_ACCOUNT_PARTITION_REVIEW_REQUIRED")
        if config.get("account_id") and config["account_id"] != self.account:
            raise InstallError("WRONG_AWS_ACCOUNT")
        if args.slack_secret_arn and not re.fullmatch(r"arn:aws:secretsmanager:" + re.escape(args.region) + ":" + self.account + r":secret:[^*?\s]+", args.slack_secret_arn):
            raise InstallError("SLACK_SECRET_ACCOUNT_REGION_REVIEW_REQUIRED")
        if args.model_arn and not re.fullmatch(r"arn:aws:bedrock:" + re.escape(args.region) + ":(?:" + self.account + r")?:(?:foundation-model|inference-profile)/[^*?\s]+", args.model_arn):
            raise InstallError("MODEL_SCOPE_REVIEW_REQUIRED")
        self.slack_secret_key_arn = self.resolve_slack_secret_key()
        self.artifacts = {}
        self.ingress = {}
        self.outputs = {}
        self.name = config["installation_id"]
        self.ops_event_bridge_rule_arns = None
        self.discovery_event_bridge_rule_arns = None

    def aws(self, *arguments, region=None):
        return self.call(*arguments, profile=self.args.profile, region=region or self.args.region)

    def resolve_slack_secret_key(self):
        """Read only encryption metadata; never fetch or print a secret value."""
        secret_arn = self.args.slack_secret_arn
        if not secret_arn:
            return ""
        secret = self.aws("secretsmanager", "describe-secret", "--secret-id", secret_arn)
        if secret.get("ARN") != secret_arn or secret.get("DeletedDate") is not None:
            raise InstallError("SLACK_SECRET_METADATA_REVIEW_REQUIRED")
        key_id = secret.get("KmsKeyId")
        # Secrets Manager omits this field for its default aws/secretsmanager key.
        if key_id is None:
            return ""
        key_suffix = r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
        scope = "arn:aws:kms:" + re.escape(self.args.region) + ":" + self.account + ":"
        local_alias = r"alias/[A-Za-z0-9/_-]{1,256}"
        if (not isinstance(key_id, str) or not re.fullmatch(
                r"(?:" + key_suffix + "|" + local_alias + "|" + scope + r"(?:key/" + key_suffix + "|" + local_alias + "))", key_id)):
            raise InstallError("SLACK_SECRET_KEY_SCOPE_REVIEW_REQUIRED")
        key = self.aws("kms", "describe-key", "--key-id", key_id).get("KeyMetadata", {})
        key_arn = key.get("Arn")
        if (not isinstance(key_arn, str) or not re.fullmatch(scope + "key/" + key_suffix, key_arn)
                or key.get("AWSAccountId") != self.account or key.get("KeyId") != key_arn.rsplit("/", 1)[-1]
                or key.get("Enabled") is not True or key.get("KeyState") != "Enabled"
                or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
                or (key.get("KeySpec") or key.get("CustomerMasterKeySpec")) != "SYMMETRIC_DEFAULT"):
            raise InstallError("SLACK_SECRET_KEY_METADATA_REVIEW_REQUIRED")
        if (re.fullmatch(key_suffix, key_id) and key_id != key["KeyId"]
                or key_id.startswith(scope + "key/") and key_id != key_arn):
            raise InstallError("SLACK_SECRET_KEY_METADATA_REVIEW_REQUIRED")
        if key.get("KeyManager") == "AWS":
            return ""
        if key.get("KeyManager") != "CUSTOMER":
            raise InstallError("SLACK_SECRET_KEY_METADATA_REVIEW_REQUIRED")
        return key_arn

    def json_argument(self, value):
        # AWS CLI accepts JSON directly in a single argv entry; no shell expansion.
        return json.dumps(value, separators=(",", ":"))

    def validate_ops_event_sources(self, value):
        if not isinstance(value, str) or len(value.encode()) > 4096:
            raise InstallError("OPERATIONAL_EVENT_SOURCE_SCOPE_REVIEW_REQUIRED")
        if value and any(not re.fullmatch(r"arn:aws:events:" + re.escape(self.args.region) + ":" + self.account + r":rule/[A-Za-z0-9._/-]+", item)
                         for item in value.split(",")):
            raise InstallError("OPERATIONAL_EVENT_SOURCE_SCOPE_REVIEW_REQUIRED")
        return value

    def existing_ops_event_sources(self):
        try:
            result = self.aws("cloudformation", "describe-stacks", "--stack-name", self.name)
        except AwsError as error:
            if error.code == "ValidationError":
                return ""
            raise
        stack = result.get("Stacks", [{}])[0]
        tags = {item["Key"]: item["Value"] for item in stack.get("Tags", [])}
        if tags.get("ManagedBy") != "enterprise-security" or tags.get("InstallationId") != self.name:
            raise InstallError("FOREIGN_STACK_REVIEW_REQUIRED")
        parameters = {item["ParameterKey"]: item.get("ParameterValue", "") for item in stack.get("Parameters", [])}
        self.discovery_event_bridge_rule_arns = self.validate_ops_event_sources(parameters.get("DiscoveryEventBridgeRuleArns", ""))
        return self.validate_ops_event_sources(parameters.get("OpsEventBridgeRuleArns", ""))

    def bucket(self, region):
        suffix = hashlib.sha256(self.name.encode()).hexdigest()[:10]
        name = f"security-artifacts-{self.account}-{region}-{suffix}"
        if len(name) > 63:
            raise InstallError("ARTIFACT_REGION_NAME_TOO_LONG")
        new = False
        try:
            self.aws("s3api", "head-bucket", "--bucket", name, "--expected-bucket-owner", self.account, region=region)
        except AwsError as error:
            if error.code not in {"404", "NoSuchBucket", "NotFound"}:
                raise
            arguments = ["s3api", "create-bucket", "--bucket", name, "--object-ownership", "BucketOwnerEnforced"]
            if region != "us-east-1":
                arguments += ["--create-bucket-configuration", self.json_argument({"LocationConstraint": region})]
            self.aws(*arguments, region=region)
            new = True
        if not new:
            tagset = self.aws("s3api", "get-bucket-tagging", "--bucket", name, "--expected-bucket-owner", self.account, region=region).get("TagSet", [])
            labels = {item["Key"]: item["Value"] for item in tagset}
            if labels.get("ManagedBy") != "enterprise-security" or labels.get("InstallationId") != self.name:
                raise InstallError("FOREIGN_ARTIFACT_BUCKET_REVIEW_REQUIRED")
            location = self.aws("s3api", "get-bucket-location", "--bucket", name, "--expected-bucket-owner", self.account, region=region).get("LocationConstraint") or "us-east-1"
            if location != region:
                raise InstallError("ARTIFACT_BUCKET_REGION_MISMATCH")
        else:
            self.aws("s3api", "put-bucket-tagging", "--bucket", name, "--expected-bucket-owner", self.account,
                     "--tagging", self.json_argument({"TagSet": [{"Key": "ManagedBy", "Value": "enterprise-security"},
                                                                  {"Key": "InstallationId", "Value": self.name}]}), region=region)
        self.aws("s3api", "put-public-access-block", "--bucket", name, "--expected-bucket-owner", self.account,
                 "--public-access-block-configuration", self.json_argument({key: True for key in
                     ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]}), region=region)
        self.aws("s3api", "put-bucket-versioning", "--bucket", name, "--expected-bucket-owner", self.account,
                 "--versioning-configuration", '{"Status":"Enabled"}', region=region)
        self.aws("s3api", "put-bucket-encryption", "--bucket", name, "--expected-bucket-owner", self.account,
                 "--server-side-encryption-configuration", '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}', region=region)
        lifecycle = {"Rules": [{"ID": "ReleaseRetention", "Status": "Enabled", "Filter": {"Prefix": ""},
                                "NoncurrentVersionExpiration": {"NoncurrentDays": 90}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]}
        self.aws("s3api", "put-bucket-lifecycle-configuration", "--bucket", name, "--expected-bucket-owner", self.account,
                 "--lifecycle-configuration", self.json_argument(lifecycle), region=region)
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        self.aws("s3api", "put-bucket-policy", "--bucket", name, "--expected-bucket-owner", self.account,
                 "--policy", self.json_argument(policy), region=region)
        return name

    def upload(self, bucket, path, region, prefix="releases"):
        checksum, encoded = sha(path)
        key = f"{prefix}/{self.manifest['release_id']}/{path.name}"
        try:
            result = self.aws("s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(path),
                              "--expected-bucket-owner", self.account, "--if-none-match", "*", "--checksum-algorithm", "SHA256",
                              "--checksum-sha256", encoded, "--metadata", self.json_argument({"sha256": checksum}), region=region)
        except AwsError as error:
            if error.code != "PreconditionFailed":
                raise
            result = self.aws("s3api", "head-object", "--bucket", bucket, "--key", key, "--expected-bucket-owner", self.account,
                              "--checksum-mode", "ENABLED", region=region)
            if result.get("Metadata", {}).get("sha256") != checksum or result.get("ChecksumSHA256") != encoded:
                raise InstallError("EXISTING_ARTIFACT_HASH_MISMATCH")
        if result.get("ChecksumSHA256") != encoded or not result.get("VersionId"):
            raise InstallError("ARTIFACT_VERSION_CHECKSUM_REQUIRED")
        return {"bucket": bucket, "key": key, "version": result["VersionId"], "code_sha256": encoded}

    def prepare_artifacts(self, regions):
        for region in regions:
            bucket = self.bucket(region)
            self.artifacts[region] = {"bucket": bucket, "runtime": self.upload(bucket, RELEASE / "runtime.zip", region)}
            if region == self.args.region:
                self.artifacts[region]["dashboard"] = self.upload(bucket, RELEASE / "dashboard.zip", region)

    def wait(self, getter, complete, failed, name):
        deadline = time.monotonic() + self.args.timeout
        last = None
        while time.monotonic() < deadline:
            value = getter()
            state = value.get("Status", value.get("StackStatus"))
            if state != last:
                print(json.dumps({"phase": name, "status": state}), flush=True)
                last = state
            if state in complete:
                return value
            if state in failed or (state and state.endswith("FAILED")):
                raise InstallError("CLOUDFORMATION_FAILED_" + str(state))
            time.sleep(4)
        raise InstallError("CLOUDFORMATION_TIMEOUT_REVIEW_REQUIRED")

    def stack(self, name, template_name, values, region):
        path = ROOT / "infrastructure" / template_name
        template = json.loads(path.read_text(encoding="utf-8"))
        parameters = template.get("Parameters", {})
        unknown = set(values) - set(parameters)
        if unknown:
            raise InstallError("Unknown template parameters: " + ",".join(sorted(unknown)))
        try:
            previous = self.aws("cloudformation", "describe-stacks", "--stack-name", name, region=region)["Stacks"][0]
        except AwsError as error:
            if error.code != "ValidationError":
                raise
            # DescribeStacks ValidationError can also indicate invalid input.
            # Generated stable stack names have already passed schema validation.
            previous = None
        if previous:
            labels = {item["Key"]: item["Value"] for item in previous.get("Tags", [])}
            if labels.get("InstallationId") != self.name or labels.get("ManagedBy") != "enterprise-security":
                raise InstallError("FOREIGN_STACK_REVIEW_REQUIRED")
            if previous["StackStatus"] not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
                raise InstallError("STACK_NOT_STABLE_REVIEW_REQUIRED")
        supplied = [{"ParameterKey": key, "ParameterValue": str(value)} for key, value in values.items()]
        if previous:
            known = {item["ParameterKey"] for item in previous.get("Parameters", [])}
            supplied += [{"ParameterKey": key, "UsePreviousValue": True} for key in parameters if key not in values and key in known]
        missing = [key for key, definition in parameters.items() if key not in values and "Default" not in definition
                   and not (previous and key in known)]
        if missing:
            raise InstallError("Missing deployment interfaces: " + ",".join(missing))
        change_name = "security-" + hashlib.sha256((self.manifest["release_id"] + str(time.time_ns())).encode()).hexdigest()[:24]
        arguments = ["cloudformation", "create-change-set", "--stack-name", name, "--change-set-name", change_name,
                     "--change-set-type", "UPDATE" if previous else "CREATE", "--parameters", self.json_argument(supplied),
                     "--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "--tags", self.json_argument([
                         {"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "InstallationId", "Value": self.name}])]
        if path.stat().st_size <= 51200:
            arguments += ["--template-body", "file://" + str(path)]
        else:
            uploaded = self.upload(self.artifacts[region]["bucket"], path, region, "templates")
            url = f"https://{uploaded['bucket']}.s3.{region}.amazonaws.com/{quote(uploaded['key'])}?versionId={quote(uploaded['version'])}"
            arguments += ["--template-url", url]
        self.aws(*arguments, region=region)
        getter = lambda: self.aws("cloudformation", "describe-change-set", "--stack-name", name, "--change-set-name", change_name, region=region)
        deadline = time.monotonic() + self.args.timeout
        while True:
            change = getter()
            if change["Status"] == "CREATE_COMPLETE":
                break
            if change["Status"] == "FAILED":
                reason = change.get("StatusReason", "")
                if previous and ("didn't contain changes" in reason or "No updates are to be performed" in reason):
                    self.aws("cloudformation", "delete-change-set", "--stack-name", name, "--change-set-name", change_name, region=region)
                    def unchanged_snapshot():
                        value = self.aws("cloudformation", "describe-stacks", "--stack-name", name, region=region)["Stacks"][0]
                        if value["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"} and not stack_contract_ready(value, template, values):
                            value["Status"] = "AWAITING_STACK_OUTPUTS"
                        return value
                    ready = self.wait(unchanged_snapshot, {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"},
                                      {"ROLLBACK_COMPLETE", "DELETE_COMPLETE"}, name)
                    return {item["OutputKey"]: item["OutputValue"] for item in ready.get("Outputs", [])}
                raise InstallError("CHANGESET_FAILED_REVIEW_REQUIRED")
            if time.monotonic() >= deadline:
                raise InstallError("CHANGESET_TIMEOUT")
            time.sleep(3)
        # Existing data, Cognito users and workload resources cannot be replaced
        # or removed by an unattended product update.
        resource_changes = {record.get("ResourceChange", {}).get("LogicalResourceId"): record.get("ResourceChange", {})
                            for record in change.get("Changes", [])}
        original_template = {}
        if previous and any(item.get("ResourceType") in {"AWS::Lambda::Permission", "AWS::Lambda::EventSourceMapping"}
                            and item.get("Replacement") == "Conditional" for item in resource_changes.values()):
            original_template = self.aws("cloudformation", "get-template", "--stack-name", name, "--template-stage", "Original", region=region)["TemplateBody"]
            if isinstance(original_template, str):
                try:
                    original_template = json.loads(original_template)
                except ValueError:
                    raise InstallError("ORIGINAL_TEMPLATE_FORMAT_REVIEW_REQUIRED") from None
            if not isinstance(original_template, dict):
                raise InstallError("ORIGINAL_TEMPLATE_FORMAT_REVIEW_REQUIRED")
        for record in change.get("Changes", []):
            detail = record.get("ResourceChange", {})
            resource = template["Resources"].get(detail.get("LogicalResourceId"), {})
            retained_version = (detail.get("ResourceType") == "AWS::Lambda::Version" and resource.get("DeletionPolicy") == "Retain"
                                and resource.get("UpdateReplacePolicy") == "Retain")
            unchanged_permission = safe_permission_refresh(detail, template, original_template, resource_changes)
            unchanged_mapping = safe_event_source_refresh(detail, template, original_template, resource_changes)
            if detail.get("Action") == "Remove" or (detail.get("Replacement") in {"True", "Conditional"} and not retained_version and not unchanged_permission and not unchanged_mapping):
                raise InstallError("DESTRUCTIVE_CHANGESET_REVIEW_REQUIRED")
        self.aws("cloudformation", "execute-change-set", "--stack-name", name, "--change-set-name", change_name,
                 "--client-request-token", change_name, region=region)
        def current_deployment():
            value = self.aws("cloudformation", "describe-stacks", "--stack-name", name, region=region)["Stacks"][0]
            events = self.aws("cloudformation", "describe-stack-events", "--stack-name", name, "--max-items", "100", region=region)
            own = next((event for event in events.get("StackEvents", []) if event.get("ClientRequestToken") == change_name
                        and event.get("ResourceType") == "AWS::CloudFormation::Stack"), None)
            value["Status"] = own["ResourceStatus"] if own else "AWAITING_STACK_EVENT"
            if value["Status"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} and not stack_contract_ready(value, template, values):
                value["Status"] = "AWAITING_STACK_OUTPUTS"
            return value
        complete = self.wait(current_deployment,
                             {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, {"ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_COMPLETE"}, name)
        actual = {item["ParameterKey"]: item.get("ParameterValue") for item in complete.get("Parameters", [])}
        if any(actual.get(key) != str(value) for key, value in values.items()):
            raise InstallError("DEPLOYMENT_PARAMETER_VERIFICATION_FAILED")
        return {item["OutputKey"]: item["OutputValue"] for item in complete.get("Outputs", [])}

    def foundation_parameters(self, automatic=False, ingress=None, approval=None):
        artifact = self.artifacts[self.args.region]
        args = argparse.Namespace(code_bucket=artifact["runtime"]["bucket"], code_key=artifact["runtime"]["key"],
            code_version=artifact["runtime"]["version"], handler="runtime.discovery.handler", runtime="python3.13",
            dashboard_code_bucket=artifact["dashboard"]["bucket"], dashboard_code_key=artifact["dashboard"]["key"],
            dashboard_code_version=artifact["dashboard"]["version"], dashboard_handler="lambda.handler", dashboard_role=None)
        result = {item["ParameterKey"]: item["ParameterValue"] for item in onboard.render_parameters(self.config, args)}
        result["AutomaticOnboardingEnabled"] = "true" if automatic else "false"
        result["IngressArnsJson"] = self.json_argument(ingress or {})
        result["ApprovalFunctionArn"] = approval or ""
        result["OpsEventBridgeRuleArns"] = self.ops_event_bridge_rule_arns or ""
        result["DiscoveryEventBridgeRuleArns"] = self.discovery_event_bridge_rule_arns or ""
        env = {"EXPECTED_ACCOUNT": self.account, "ENVIRONMENT": self.config["environment"], "CONTROL_PLANE_REGION": self.args.region,
            "INSTALLATION_ID": self.name, "INSTALLATION_SCOPE": result["InstallationScope"], "DISCOVERY_REGIONS": result["DiscoveryRegions"],
            "RESPONSE_MODE": result["ResponseMode"], "ALLOWED_ACTIONS": result["AllowedActions"], "PRINCIPAL_SCOPES_JSON": result["PrincipalScopesJson"],
            "EXCLUDE_TAGS_JSON": result["ExcludeTagsJson"], "INGRESS_ARNS_JSON": result["IngressArnsJson"], "LOG_RETENTION_DAYS": "90"}
        for variable, output in {"REGISTRY_TABLE": "RegistryTableName", "LEASE_TABLE": "LeaseTableName", "EXPECTED_ACTIVITY_TABLE": "ExpectedActivityTableName",
                                 "AUDIT_BUCKET": "AuditBucketName", "EVENT_BUS_ARN": "SecurityEventBusArn", "SECURITY_LOG_INGRESS_ARN": "SecurityLogIngressArn"}.items():
            env[variable] = self.outputs.get(output, "generated-resource-" + "x" * 130)
        environment_budget(env)
        return result

    def verify(self, foundation, governance):
        for output, artifact in [("DiscoveryFunctionArn", "runtime"), ("DashboardFunctionArn", "dashboard")]:
            function = self.aws("lambda", "get-function-configuration", "--function-name", foundation[output])
            if function.get("CodeSha256") != self.artifacts[self.args.region][artifact]["code_sha256"] or function.get("State") != "Active":
                raise InstallError("FUNCTION_CODE_OR_STATE_MISMATCH")
        for output, function_arn in governance.items():
            if not output.endswith("FunctionArn"):
                continue
            if not function_arn.startswith(f"arn:aws:lambda:{self.args.region}:{self.account}:function:"):
                raise InstallError("GOVERNANCE_FUNCTION_SCOPE_MISMATCH")
            function = self.aws("lambda", "get-function-configuration", "--function-name", function_arn)
            if function.get("CodeSha256") != self.artifacts[self.args.region]["runtime"]["code_sha256"] or function.get("State") != "Active":
                raise InstallError("GOVERNANCE_CODE_OR_STATE_MISMATCH")
        for region, function_arn in self.ingress.items():
            if not function_arn.startswith(f"arn:aws:lambda:{region}:{self.account}:function:"):
                raise InstallError("INGRESS_FUNCTION_SCOPE_MISMATCH")
            function = self.aws("lambda", "get-function-configuration", "--function-name", function_arn, region=region)
            if function.get("CodeSha256") != self.artifacts[region]["runtime"]["code_sha256"] or function.get("State") != "Active":
                raise InstallError("INGRESS_CODE_OR_STATE_MISMATCH")
        client = self.aws("cognito-idp", "describe-user-pool-client", "--user-pool-id", foundation["CognitoUserPoolId"],
                          "--client-id", foundation["CognitoClientId"])["UserPoolClient"]
        origin = foundation["DashboardUrl"]
        if client.get("ClientSecret") or client.get("AllowedOAuthFlows") != ["code"] or client.get("CallbackURLs") != [origin + "/auth/callback"] or client.get("LogoutURLs") != [origin + "/auth/logged-out"]:
            raise InstallError("COGNITO_CLIENT_BOUNDARY_MISMATCH")
        pool = self.aws("cognito-idp", "describe-user-pool", "--user-pool-id", foundation["CognitoUserPoolId"])["UserPool"]
        if pool.get("MfaConfiguration") != "ON" or not pool.get("AdminCreateUserConfig", {}).get("AllowAdminCreateUserOnly"):
            raise InstallError("COGNITO_POOL_BOUNDARY_MISMATCH")
        if not governance.get("ApprovalFunctionArn", "").startswith(f"arn:aws:lambda:{self.args.region}:{self.account}:function:"):
            raise InstallError("APPROVAL_FUNCTION_SCOPE_MISMATCH")
        approval = governance["ApprovalFunctionArn"].split(":function:", 1)[1].split(":")
        if len(approval) != 2:
            raise InstallError("APPROVAL_ALIAS_REQUIRED")
        alias = self.aws("lambda", "get-alias", "--function-name", approval[0], "--name", approval[1])
        if alias.get("AliasArn") != governance["ApprovalFunctionArn"] or not str(alias.get("FunctionVersion", "")).isdigit():
            raise InstallError("APPROVAL_ALIAS_VERIFICATION_FAILED")
        try:
            with urlopen(origin + "/healthz", timeout=15) as response:
                if response.status != 200:
                    raise InstallError("DASHBOARD_HEALTH_FAILED")
        except InstallError:
            raise
        except Exception:
            raise InstallError("DASHBOARD_HEALTH_FAILED") from None
        return {"code_hashes": "VERIFIED", "cognito": "MFA_ADMIN_ONLY_PKCE_CONFIGURED", "dashboard_health": "PASSED"}

    def invoke_discovery(self, function, operation):
        with tempfile.TemporaryDirectory(prefix="enterprise-install-") as directory:
            request, response = Path(directory) / "request.json", Path(directory) / "response.json"
            request.write_text(self.json_argument({"operation": operation}), encoding="utf-8")
            invocation = self.aws("lambda", "invoke", "--function-name", function, "--invocation-type", "RequestResponse",
                                  "--cli-binary-format", "raw-in-base64-out", "--payload", "fileb://" + str(request), str(response))
            if invocation.get("FunctionError") or invocation.get("StatusCode") != 200:
                raise InstallError("DISCOVERY_BACKEND_FAILED")
            return onboard.safe_report(json.loads(response.read_text(encoding="utf-8")))

    def bootstrap_admin(self, foundation):
        if not self.args.admin_email:
            return "NOT_REQUESTED"
        # This operator-supplied flag authorizes the Cognito invitation.
        created = True
        try:
            self.aws("cognito-idp", "admin-create-user", "--user-pool-id", foundation["CognitoUserPoolId"],
                     "--username", self.args.admin_email, "--desired-delivery-mediums", "EMAIL", "--user-attributes",
                     self.json_argument([{"Name": "email", "Value": self.args.admin_email}, {"Name": "email_verified", "Value": "true"}]))
        except AwsError as error:
            if error.code != "UsernameExistsException":
                raise
            created = False
            existing = self.aws("cognito-idp", "admin-get-user", "--user-pool-id", foundation["CognitoUserPoolId"], "--username", self.args.admin_email)
            attrs = {item["Name"]: item["Value"] for item in existing.get("UserAttributes", [])}
            if attrs.get("email") != self.args.admin_email or attrs.get("email_verified") != "true":
                raise InstallError("EXISTING_ADMIN_IDENTITY_REVIEW_REQUIRED")
        self.aws("cognito-idp", "admin-add-user-to-group", "--user-pool-id", foundation["CognitoUserPoolId"],
                 "--username", self.args.admin_email, "--group-name", foundation["AdminGroupName"])
        return "INVITATION_REQUESTED_MFA_REQUIRED" if created else "EXISTING_VERIFIED_ADMIN_MFA_REQUIRED"

    def apply(self):
        plan = installation_plan(self.config, self.args, self.manifest)
        # Preserve the working key grants throughout updates before rewiring
        # exact old+new rule identities from this deployment's own governance.
        self.ops_event_bridge_rule_arns = self.existing_ops_event_sources()
        self.prepare_artifacts(plan["artifact_and_ingress_regions"])
        foundation = self.stack(self.name, "foundation.template.json", self.foundation_parameters(), self.args.region)
        self.discovery_event_bridge_rule_arns = self.validate_ops_event_sources(",".join([
            foundation["DiscoveryScheduleRuleArn"], foundation["DiscoveryResourceEventRuleArn"]]))
        self.outputs = foundation
        ingress = {self.args.region: foundation["SecurityLogIngressArn"]}
        for region in plan["artifact_and_ingress_regions"]:
            if region == self.args.region:
                continue
            code = self.artifacts[region]["runtime"]
            params = {"CodeBucket": code["bucket"], "CodeKey": code["key"], "CodeVersion": code["version"],
                      "Environment": self.config["environment"], "ControlPlaneRegion": self.args.region, "InstallationId": self.name}
            for field in ["RegistryTableName", "RegistryTableArn", "ExpectedActivityTableName", "ExpectedActivityTableArn",
                          "CasesTableName", "CasesTableArn", "SecurityEventBusArn", "AuditBucketName", "AuditBucketArn", "AuditKeyArn", "LeaseTableName", "LeaseTableArn"]:
                params[field] = foundation[field]
            shard = self.stack(self.name + "-ingress", "security-log-ingress.template.json", params, region)
            ingress[region] = shard["SecurityLogIngressArn"]
        runtime = self.artifacts[self.args.region]["runtime"]
        parameters = {"RuntimeCodeBucket": runtime["bucket"], "RuntimeCodeKey": runtime["key"], "RuntimeCodeVersion": runtime["version"],
                      "RuntimeCodeSha256": runtime["code_sha256"], "Environment": self.config["environment"],
                      "DefaultDryRun": "false" if self.args.enable_enforcement else "true",
                      "SlackSecretArn": self.args.slack_secret_arn or "", "SlackChannelId": self.args.slack_channel_id or "",
                      "SlackSecretKeyArn": self.slack_secret_key_arn,
                      "IngressAlarmNames": plan["ingress_alarm_names"],
                      "ModelArn": self.args.model_arn or ""}
        mappings = {"OperationsTableName": "ResponseOperationsTableName", "OperationsTableArn": "ResponseOperationsTableArn",
                    "ReceiptTableName": "PublicationReceiptsTableName", "ReceiptTableArn": "PublicationReceiptsTableArn"}
        template = json.loads((ROOT / "infrastructure/control_plane.template.json").read_text(encoding="utf-8"))
        for field in template["Parameters"]:
            source = mappings.get(field, field)
            if source in foundation:
                parameters[field] = foundation[source]
        # Unsupported interface drift is a build error rather than silently
        # omitting a function, timer, or security policy.
        parameters = {key: value for key, value in parameters.items() if key in template["Parameters"]}
        if "RuntimeConfigRevision" in template["Parameters"]:
            parameters["RuntimeConfigRevision"] = hashlib.sha256(self.json_argument(dict(sorted(parameters.items()))).encode()).hexdigest()
        governance = self.stack(self.name + "-governance", "control_plane.template.json", parameters, self.args.region)
        self.ops_event_bridge_rule_arns = self.validate_ops_event_sources(governance["OpsEventBridgeRuleArns"])
        self.ingress = ingress
        foundation = self.stack(self.name, "foundation.template.json", self.foundation_parameters(False, ingress, governance["ApprovalFunctionArn"]), self.args.region)
        verification = self.verify(foundation, governance)
        validation_only = getattr(self.args, "validation_only", False)
        if not validation_only:
            foundation = self.stack(self.name, "foundation.template.json", self.foundation_parameters(True, ingress, governance["ApprovalFunctionArn"]), self.args.region)
        candidates = self.invoke_discovery(foundation["DiscoveryFunctionArn"], "discover")
        reconciled = {"operation": "NOT_EXECUTED_VALIDATION_ONLY", "resources": []} if validation_only else self.invoke_discovery(foundation["DiscoveryFunctionArn"], "reconcile")
        rows = reconciled.get("resources", reconciled.get("results", []))
        review = any(row.get("status") in {"REVIEW_REQUIRED", "FAILED"} for row in rows)
        status = "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED" if validation_only else "DEPLOYED_REVIEW_REQUIRED" if review else "DEPLOYED_CONNECTED" if rows else "DEPLOYED_NO_ELIGIBLE_RESOURCES"
        result = {"status": status, "installation_id": self.name, "account_id": self.account, "release_id": self.manifest["release_id"],
                  "dashboard_url": foundation["DashboardUrl"], "verification": verification, "discovery": candidates,
                  "onboarding": reconciled, "admin_bootstrap": self.bootstrap_admin(foundation),
                  "business_application_deployed": False, "end_to_end_response_acceptance": "OPERATOR_TEST_REQUIRED"}
        result["automatic_onboarding_enabled"] = not validation_only
        destination = ROOT / "build" / "install-result.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--allow-all-supported", action="store_true")
    parser.add_argument("--enable-enforcement", action="store_true")
    parser.add_argument("--validation-only", action="store_true", help="Deploy and verify platform; keep automatic onboarding disabled and never reconcile WAF")
    parser.add_argument("--admin-email")
    parser.add_argument("--slack-secret-arn")
    parser.add_argument("--slack-channel-id")
    parser.add_argument("--model-arn")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    config = onboard.validate(json.loads(args.config.read_text(encoding="utf-8")))
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", args.region) or not 30 <= args.timeout <= 3600:
        parser.error("Valid region and timeout 30..3600 required")
    if args.apply and config["discovery"]["scope"] == "all-supported" and not args.allow_all_supported:
        parser.error("all-supported requires --allow-all-supported")
    if args.enable_enforcement and config["response_mode"] != "enforce":
        parser.error("--enable-enforcement requires response_mode=enforce")
    if args.validation_only and (args.enable_enforcement or args.admin_email or args.slack_secret_arn):
        parser.error("--validation-only requires dry run, no admin invitation, and notifications disabled")
    if args.validation_only and config["response_mode"] != "observe":
        parser.error("--validation-only requires observe mode")
    if bool(args.slack_secret_arn) != bool(args.slack_channel_id):
        parser.error("Slack secret ARN and channel ID must be supplied together")
    if args.slack_channel_id and not re.fullmatch(r"[CG][A-Z0-9]{8,32}", args.slack_channel_id):
        parser.error("Invalid Slack channel ID")
    if args.admin_email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", args.admin_email):
        parser.error("Invalid operator admin email")
    manifest = verified_release() if args.apply else None
    result = Installer(config, args, manifest).apply() if args.apply else installation_plan(config, args)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
