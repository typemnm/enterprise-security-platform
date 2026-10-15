"""Resolve Terraform outputs against live, installation-owned AWS resources.

An output file is a locator, never an authorization grant. This module reads
only bounded metadata and selected non-secret configuration. It makes no AWS
writes and does not depend on a CloudFormation stack surviving an ownership
handoff. Legacy callers keep their existing CloudFormation verification path.
"""
import json
from pathlib import Path
import re


class DeploymentError(ValueError):
    """Bounded operator-facing error; never includes submitted values."""


def require(condition, code):
    if not condition:
        raise DeploymentError(code)


def _object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "DUPLICATE_DEPLOYMENT_FIELD")
        result[name] = value
    return result


def load(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= 262144, "DEPLOYMENT_OUTPUTS_TOO_LARGE")
    document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object)
    require(isinstance(document, dict), "TERRAFORM_DEPLOYMENT_OUTPUT_REQUIRED")
    # `output -json deployment` emits the value; `output -json` wraps it.
    value = document if document.get("schema_version") == "2.0" else None
    if value is None and isinstance(document.get("deployment"), dict):
        value = document["deployment"].get("value")
    require(isinstance(value, dict), "TERRAFORM_DEPLOYMENT_VALUE_REQUIRED")
    require(value.get("schema_version") == "2.0" and value.get("deployment_method") == "terraform", "UNSUPPORTED_DEPLOYMENT_CONTRACT")
    for field, pattern in (("installation_id", r"[a-z][a-z0-9-]{2,30}"), ("account_id", r"\d{12}"),
                           ("control_plane_region", r"[a-z]{2}(?:-[a-z]+)+-\d"), ("release_id", r"[a-f0-9]{64}")):
        require(isinstance(value.get(field), str) and re.fullmatch(pattern, value[field]), "INVALID_DEPLOYMENT_IDENTITY")
    require(type(value.get("automatic_onboarding_enabled")) is bool and type(value.get("default_dry_run")) is bool,
            "EXPLICIT_DEPLOYMENT_POLICY_REQUIRED")
    require(isinstance(value.get("outputs"), dict) and value["outputs"] and
            all(isinstance(k, str) and isinstance(v, str) and len(v) <= 8192 for k, v in value["outputs"].items()),
            "INVALID_DEPLOYMENT_RESOURCE_OUTPUTS")
    require(isinstance(value.get("ingress_arns"), dict) and value["ingress_arns"], "DEPLOYMENT_INGRESS_MAPPING_REQUIRED")
    return value


FUNCTIONS = {"DiscoveryFunctionArn": "runtime.discovery.handler", "DashboardFunctionArn": "lambda.handler",
             "SignalIngressFunctionArn": "runtime.case_pipeline.handler", "ApprovalFunctionArn": "runtime.approval.handler",
             "ReconcilerFunctionArn": "runtime.publication_reconciler.handler", "NotifierFunctionArn": "runtime.notifier.handler",
             "TerminalFunctionArn": "runtime.terminal.handler", "OpsFunctionArn": "runtime.ops.handler",
             "BlockerFunctionArn": "runtime.blocker.handler", "OutboxFunctionArn": "runtime.outbox_delivery.handler"}
TABLES = ("Registry", "Lease", "ExpectedActivity", "Cases", "ResponseOperations", "PublicationReceipts", "DashboardSession")
ENV_FIELDS = ("EXPECTED_ACCOUNT", "CONTROL_PLANE_REGION", "INSTALLATION_ID", "ENVIRONMENT", "REGISTRY_TABLE", "LEASE_TABLE",
              "EXPECTED_ACTIVITY_TABLE", "CASES_TABLE", "OPERATIONS_TABLE", "AUDIT_BUCKET", "EVENT_BUS_ARN", "INSTALLATION_SCOPE",
              "DISCOVERY_REGIONS", "RESPONSE_MODE", "ALLOWED_ACTIONS", "INGRESS_ARNS_JSON", "SECURITY_LOG_INGRESS_ARN",
              "DEFAULT_DRY_RUN", "NOTIFICATIONS_ENABLED", "SLACK_SECRET_ARN", "SLACK_CHANNEL_ID", "MODEL_ARN", "QUEUE_URL",
              "PIPELINE_STATE_MACHINE_ARN", "PUBLIC_ORIGIN", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_REDIRECT_URI", "SESSION_TABLE",
              "SERVICE_REGISTRY_TABLE", "REPORT_BUCKET", "APPROVE_FUNCTION_NAME")


class VerifiedDeployment:
    def __init__(self, document, *, installation_id, account_id, profile, region, call):
        self.document, self.profile, self.region, self.call = document, profile, region, call
        self.name, self.account = document["installation_id"], document["account_id"]
        require(self.name == installation_id and document["control_plane_region"] == region
                and (account_id is None or self.account == account_id), "DEPLOYMENT_IDENTITY_MISMATCH")
        self.outputs, self.ingress_arns = document["outputs"], document["ingress_arns"]
        self._functions, self._tables = {}, set()

    def aws(self, *arguments, region=None):
        return self.call(*arguments, profile=self.profile, region=region or self.region)

    def ownership(self, tags):
        if isinstance(tags, list):
            tags = {row.get("Key", row.get("key")): row.get("Value", row.get("value")) for row in tags if isinstance(row, dict)}
        require(isinstance(tags, dict) and tags.get("ManagedBy") == "enterprise-security"
                and tags.get("InstallationId") == self.name, "DEPLOYMENT_RESOURCE_OWNERSHIP_MISMATCH")

    def arn(self, value, service, *, region=None, suffix=None):
        selected = self.region if region is None else region
        require(isinstance(value, str) and value.startswith(f"arn:aws:{service}:{selected}:{self.account}:")
                and (suffix is None or value.split(":", 5)[5].startswith(suffix)), "DEPLOYMENT_RESOURCE_SCOPE_MISMATCH")
        return value

    def function_config(self, arn, *, region=None):
        selected = region or self.region
        if arn in self._functions:
            return self._functions[arn]
        self.arn(arn, "lambda", region=selected, suffix="function:")
        require(re.fullmatch(r"arn:aws:lambda:" + re.escape(selected) + ":" + self.account + r":function:[A-Za-z0-9_-]+(?::live)?", arn),
                "DEPLOYMENT_FUNCTION_SCOPE_MISMATCH")
        base = arn.rsplit(":", 1)[0] if arn.endswith(":live") else arn
        self.ownership(self.aws("lambda", "list-tags", "--resource", base, region=selected).get("Tags"))
        fields = ",".join(name + ":" + name for name in ENV_FIELDS)
        query = "{FunctionArn:FunctionArn,Version:Version,CodeSha256:CodeSha256,State:State,Handler:Handler,Role:Role,Environment:Environment.Variables.{" + fields + "}}"
        row = self.aws("lambda", "get-function-configuration", "--function-name", arn, "--query", query, region=selected)
        require(row.get("State") == "Active" and row.get("FunctionArn") in {arn, base, base + ":" + str(row.get("Version", ""))},
                "DEPLOYMENT_FUNCTION_NOT_ACTIVE")
        if arn.endswith(":live"):
            alias = self.aws("lambda", "get-alias", "--function-name", base, "--name", "live", region=selected)
            require(alias.get("AliasArn") == arn and str(alias.get("FunctionVersion", "")).isdigit()
                    and alias.get("FunctionVersion") == row.get("Version"), "DEPLOYMENT_ALIAS_NOT_PINNED")
        env = row.get("Environment", {})
        require(isinstance(env, dict), "DEPLOYMENT_FUNCTION_ENVIRONMENT_REQUIRED")
        self._functions[arn] = row
        return row

    def verify_table(self, name, arn):
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", name)
                and arn == f"arn:aws:dynamodb:{self.region}:{self.account}:table/{name}", "DEPLOYMENT_TABLE_SCOPE_MISMATCH")
        if arn not in self._tables:
            row = self.aws("dynamodb", "describe-table", "--table-name", name, "--query", "Table.{TableArn:TableArn,TableStatus:TableStatus}")
            require(row.get("TableArn") == arn and row.get("TableStatus") == "ACTIVE", "DEPLOYMENT_TABLE_NOT_ACTIVE")
            self.ownership(self.aws("dynamodb", "list-tags-of-resource", "--resource-arn", arn).get("Tags"))
            self._tables.add(arn)

    def _role(self, arn, *, region=None):
        self.arn(arn, "iam", region="", suffix="role/")
        role = arn.split("/", 1)[1]
        require("/" not in role and re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", role), "DEPLOYMENT_ROLE_SCOPE_MISMATCH")
        row = self.aws("iam", "get-role", "--role-name", role, "--query", "Role.{Arn:Arn,Tags:Tags}", region=region)
        require(row.get("Arn") == arn, "DEPLOYMENT_ROLE_ARN_MISMATCH")
        self.ownership(row.get("Tags"))

    def ingress_configuration(self, region):
        require(region in self.ingress_arns, "DEPLOYMENT_INGRESS_REGION_NOT_INSTALLED")
        config = self.function_config(self.ingress_arns[region], region=region)
        require(config.get("Handler") == "runtime.ingest.handler", "DEPLOYMENT_INGRESS_HANDLER_MISMATCH")
        env, out = config["Environment"], self.outputs
        for field, expected in {"EXPECTED_ACCOUNT": self.account, "CONTROL_PLANE_REGION": self.region, "INSTALLATION_ID": self.name,
                                "REGISTRY_TABLE": out["RegistryTableName"], "LEASE_TABLE": out["LeaseTableName"],
                                "CASES_TABLE": out["CasesTableName"], "EVENT_BUS_ARN": out["SecurityEventBusArn"],
                                "AUDIT_BUCKET": out["AuditBucketName"]}.items():
            require(env.get(field) == expected, "DEPLOYMENT_INGRESS_BINDING_MISMATCH")
        self._role(config.get("Role"), region=region)
        return config

    def verify(self):
        identity = self.aws("sts", "get-caller-identity")
        require(identity.get("Account") == self.account and isinstance(identity.get("Arn"), str)
                and re.fullmatch(r"arn:aws:(?:iam|sts)::" + self.account + r":.+", identity["Arn"]), "DEPLOYMENT_STS_ACCOUNT_MISMATCH")
        out = self.outputs
        require(out.get("InstallationId") == self.name, "DEPLOYMENT_INSTALLATION_OUTPUT_MISMATCH")
        # Reject foreign or malformed locators before querying any resource.
        for key, value in out.items():
            if key.endswith("Arn") and not key.endswith("Arns"):
                parts = value.split(":", 5)
                require(len(parts) == 6 and parts[:2] == ["arn", "aws"] and
                        ((parts[2] == "s3" and parts[3:5] == ["", ""]) or parts[4] == self.account), "DEPLOYMENT_OUTPUT_ARN_ACCOUNT_MISMATCH")
        for stem in TABLES:
            self.verify_table(out.get(stem + "TableName"), out.get(stem + "TableArn"))
        require(out.get("ReceiptTableName") == out.get("PublicationReceiptsTableName")
                and out.get("ReceiptTableArn") == out.get("PublicationReceiptsTableArn"), "DEPLOYMENT_RECEIPT_TABLE_BINDING_MISMATCH")
        for field, handler in FUNCTIONS.items():
            row = self.function_config(out.get(field))
            require(row.get("Handler") == handler, "DEPLOYMENT_FUNCTION_HANDLER_MISMATCH")
        discovery = self.function_config(out["DiscoveryFunctionArn"])["Environment"]
        for field, expected in {"EXPECTED_ACCOUNT": self.account, "INSTALLATION_ID": self.name, "CONTROL_PLANE_REGION": self.region,
                                "REGISTRY_TABLE": out["RegistryTableName"], "LEASE_TABLE": out["LeaseTableName"],
                                "AUDIT_BUCKET": out["AuditBucketName"], "EVENT_BUS_ARN": out["SecurityEventBusArn"]}.items():
            require(discovery.get(field) == expected, "DEPLOYMENT_DISCOVERY_BINDING_MISMATCH")
        configured = json.loads(discovery.get("INGRESS_ARNS_JSON", "{}"), object_pairs_hook=_object)
        require(configured == self.ingress_arns, "DEPLOYMENT_INGRESS_MAPPING_MISMATCH")
        for region in self.ingress_arns:
            require(isinstance(region, str) and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region), "INVALID_DEPLOYMENT_INGRESS_REGION")
            self.ingress_configuration(region)
        require(self.ingress_arns.get(self.region) == out.get("SecurityLogIngressArn"), "DEPLOYMENT_CONTROL_INGRESS_BINDING_MISMATCH")
        pipeline = self.function_config(out["SignalIngressFunctionArn"])
        env = pipeline["Environment"]
        machine = self.arn(out.get("PipelineStateMachineArn"), "states", suffix="stateMachine:")
        require(machine == f"arn:aws:states:{self.region}:{self.account}:stateMachine:{self.name}-governance-pipeline", "DEPLOYMENT_WORKFLOW_NAME_MISMATCH")
        actual = self.aws("stepfunctions", "describe-state-machine", "--state-machine-arn", machine, "--included-data", "METADATA_ONLY", "--query", "{stateMachineArn:stateMachineArn,status:status}")
        require(actual.get("stateMachineArn") == machine and actual.get("status") == "ACTIVE", "DEPLOYMENT_WORKFLOW_NOT_ACTIVE")
        self.ownership(self.aws("stepfunctions", "list-tags-for-resource", "--resource-arn", machine).get("tags"))
        for field, expected in {"EXPECTED_ACCOUNT": self.account, "REGISTRY_TABLE": out["RegistryTableName"], "CASES_TABLE": out["CasesTableName"],
                                "OPERATIONS_TABLE": out["ResponseOperationsTableName"], "LEASE_TABLE": out["LeaseTableName"],
                                "PIPELINE_STATE_MACHINE_ARN": machine, "DEFAULT_DRY_RUN": str(self.document["default_dry_run"]).lower()}.items():
            require(env.get(field) == expected, "DEPLOYMENT_PIPELINE_BINDING_MISMATCH")
        self._dashboard()
        self._queue()
        automatic = []
        for field in ("DiscoveryScheduleRuleArn", "DiscoveryResourceEventRuleArn"):
            rule = self.rule(out.get(field))
            targets = self.aws("events", "list-targets-by-rule", "--rule", rule["Name"], "--event-bus-name", rule.get("EventBusName", "default"))
            require(not targets.get("NextToken") and any(item.get("Arn") == out["DiscoveryFunctionArn"] for item in targets.get("Targets", [])), "DEPLOYMENT_DISCOVERY_RULE_BINDING_MISMATCH")
            automatic.append(rule.get("State") == "ENABLED")
        require(automatic == [self.document["automatic_onboarding_enabled"]] * 2, "DEPLOYMENT_AUTOMATIC_POLICY_MISMATCH")
        self.foundation_parameters = {"InstallationScope": discovery.get("INSTALLATION_SCOPE"), "ResponseMode": discovery.get("RESPONSE_MODE"),
            "Environment": discovery.get("ENVIRONMENT"), "DiscoveryRegions": discovery.get("DISCOVERY_REGIONS"), "AllowedActions": discovery.get("ALLOWED_ACTIONS"),
            "AutomaticOnboardingEnabled": str(automatic[0]).lower(), "IngressArnsJson": json.dumps(self.ingress_arns, separators=(",", ":"))}
        notifier = self.function_config(out["NotifierFunctionArn"])["Environment"]
        self.governance_parameters = {"RuntimeCodeSha256": pipeline["CodeSha256"], "DefaultDryRun": env.get("DEFAULT_DRY_RUN"),
            "SlackSecretArn": notifier.get("SLACK_SECRET_ARN", ""), "SlackChannelId": notifier.get("SLACK_CHANNEL_ID", ""), "ModelArn": env.get("MODEL_ARN", ""),
            "RegistryTableName": out["RegistryTableName"], "CasesTableName": out["CasesTableName"], "OperationsTableName": out["ResponseOperationsTableName"], "AuditBucketName": out["AuditBucketName"]}
        return self

    def _dashboard(self):
        out = self.outputs
        dashboard = self.function_config(out["DashboardFunctionArn"])["Environment"]
        pool = out.get("CognitoUserPoolId")
        require(isinstance(pool, str) and re.fullmatch(re.escape(self.region) + r"_[A-Za-z0-9]+", pool), "DEPLOYMENT_COGNITO_POOL_SCOPE_MISMATCH")
        issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{pool}"
        require(out.get("OidcIssuer") == issuer and dashboard.get("OIDC_ISSUER") == issuer and dashboard.get("OIDC_CLIENT_ID") == out.get("CognitoClientId")
                and dashboard.get("OIDC_REDIRECT_URI") == out.get("DashboardRedirectUri") == out.get("DashboardUrl", "") + "/auth/callback"
                and dashboard.get("PUBLIC_ORIGIN") == out.get("DashboardUrl") and dashboard.get("SERVICE_REGISTRY_TABLE") == out["RegistryTableName"]
                and dashboard.get("SESSION_TABLE") == out["DashboardSessionTableName"] and dashboard.get("CASES_TABLE") == out["CasesTableName"]
                and dashboard.get("APPROVE_FUNCTION_NAME") == out["ApprovalFunctionArn"], "DEPLOYMENT_DASHBOARD_BINDING_MISMATCH")
        row = self.aws("cognito-idp", "describe-user-pool", "--user-pool-id", pool, "--query", "UserPool.{Id:Id,Arn:Arn,UserPoolTags:UserPoolTags}")
        require(row.get("Id") == pool and row.get("Arn") == f"arn:aws:cognito-idp:{self.region}:{self.account}:userpool/{pool}", "DEPLOYMENT_COGNITO_POOL_MISMATCH")
        self.ownership(row.get("UserPoolTags"))
        client = self.aws("cognito-idp", "describe-user-pool-client", "--user-pool-id", pool, "--client-id", out["CognitoClientId"],
            "--query", "UserPoolClient.{UserPoolId:UserPoolId,ClientId:ClientId,CallbackURLs:CallbackURLs,AllowedOAuthFlows:AllowedOAuthFlows}")
        require(client.get("UserPoolId") == pool and client.get("ClientId") == out["CognitoClientId"] and out["DashboardRedirectUri"] in client.get("CallbackURLs", [])
                and client.get("AllowedOAuthFlows") == ["code"], "DEPLOYMENT_COGNITO_CLIENT_MISMATCH")
        generated = re.fullmatch(r"https://([a-z0-9]+)\.execute-api\." + re.escape(self.region) + r"\.amazonaws\.com", out["DashboardUrl"])
        api = out.get("DashboardApiId") or out.get("DashboardHttpApiId") or (generated.group(1) if generated else None)
        require(isinstance(api, str) and re.fullmatch(r"[a-z0-9]+", api), "DEPLOYMENT_DASHBOARD_API_ID_REQUIRED")
        row = self.aws("apigatewayv2", "get-api", "--api-id", api)
        require(row.get("ApiId") == api and row.get("ProtocolType") == "HTTP" and (not generated or row.get("ApiEndpoint") == out["DashboardUrl"]), "DEPLOYMENT_DASHBOARD_API_MISMATCH")
        self.ownership(row.get("Tags"))
        integrations = self.aws("apigatewayv2", "get-integrations", "--api-id", api)
        require(not integrations.get("NextToken") and any(item.get("IntegrationType") == "AWS_PROXY" and item.get("IntegrationUri") == out["DashboardFunctionArn"]
                for item in integrations.get("Items", [])), "DEPLOYMENT_DASHBOARD_API_BINDING_MISMATCH")

    def _queue(self):
        out = self.outputs
        queue, arn = out.get("NotificationQueueUrl"), out.get("NotificationQueueArn")
        require(isinstance(queue, str) and re.fullmatch(r"https://sqs\." + re.escape(self.region) + r"\.amazonaws\.com/" + self.account + r"/[A-Za-z0-9_-]+", queue)
                and arn == f"arn:aws:sqs:{self.region}:{self.account}:" + queue.rsplit("/", 1)[-1], "DEPLOYMENT_QUEUE_SCOPE_MISMATCH")
        actual = self.aws("sqs", "get-queue-attributes", "--queue-url", queue, "--attribute-names", "QueueArn").get("Attributes", {})
        require(actual.get("QueueArn") == arn, "DEPLOYMENT_QUEUE_ARN_MISMATCH")
        self.ownership(self.aws("sqs", "list-queue-tags", "--queue-url", queue).get("Tags"))
        env = self.function_config(out["NotifierFunctionArn"])["Environment"]
        require(env.get("QUEUE_URL") == queue and env.get("REGISTRY_TABLE") == out["RegistryTableName"] and env.get("CASES_TABLE") == out["CasesTableName"],
                "DEPLOYMENT_NOTIFIER_BINDING_MISMATCH")

    def rule(self, arn):
        self.arn(arn, "events", suffix="rule/")
        path = arn.split(":", 5)[5][5:].split("/")
        require(len(path) in (1, 2) and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in path), "DEPLOYMENT_RULE_SCOPE_MISMATCH")
        bus, name = ("default", path[0]) if len(path) == 1 else path
        row = self.aws("events", "describe-rule", "--name", name, "--event-bus-name", bus)
        require(row.get("Arn") == arn and row.get("Name") == name and row.get("EventBusName", "default") == bus
                and row.get("State") in {"ENABLED", "DISABLED"}, "DEPLOYMENT_RULE_METADATA_MISMATCH")
        self.ownership(self.aws("events", "list-tags-for-resource", "--resource-arn", arn).get("Tags"))
        return row

    def resource(self, logical, *, scope="foundation", region=None):
        selected = region or self.region
        if logical == "NotificationQueue" and scope == "governance":
            return self.outputs["NotificationQueueUrl"]
        if logical == "SecurityLogIngressFunction":
            return self.ingress_configuration(selected)["FunctionArn"]
        if logical == "SecurityLogIngressRole":
            return self.ingress_configuration(selected)["Role"].rsplit("/", 1)[-1]
        if logical == "IngressErrorsAlarm":
            name = self.name + "-" + selected + "-log-ingress-errors"
            rows = self.aws("cloudwatch", "describe-alarms", "--alarm-names", name, region=selected).get("MetricAlarms", [])
            arn = f"arn:aws:cloudwatch:{selected}:{self.account}:alarm:{name}"
            require(len(rows) == 1 and rows[0].get("AlarmArn") == arn, "DEPLOYMENT_ALARM_SCOPE_MISMATCH")
            self.ownership(self.aws("cloudwatch", "list-tags-for-resource", "--resource-arn", arn, region=selected).get("Tags"))
            return name
        if logical in {"IngressAlarmStateChangeRelay", "IngressOpsRule"}:
            name = self.name + ("-ingress-ops" if logical == "IngressOpsRule" else "-" + selected + "-ingress-relay")
            bus = self.outputs["SecurityEventBusName"] if logical == "IngressOpsRule" else "default"
            arn = f"arn:aws:events:{selected}:{self.account}:rule/" + ("" if bus == "default" else bus + "/") + name
            row = self.aws("events", "describe-rule", "--name", name, "--event-bus-name", bus, region=selected)
            require(row.get("Arn") == arn and row.get("Name") == name and row.get("State") == "ENABLED", "DEPLOYMENT_RULE_METADATA_MISMATCH")
            self.ownership(self.aws("events", "list-tags-for-resource", "--resource-arn", arn, region=selected).get("Tags"))
            return name if bus == "default" else bus + "|" + name
        raise DeploymentError("UNSUPPORTED_DEPLOYMENT_RESOURCE_LOOKUP")


def resolve_terraform(path, *, installation_id, account_id=None, profile, region, call):
    return VerifiedDeployment(load(path), installation_id=installation_id, account_id=account_id, profile=profile, region=region, call=call).verify()


def installation_result(path=None, *, deployment_outputs=None, legacy_path=None):
    """Read a legacy receipt or Terraform locators; live guards remain mandatory."""
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=_object)
    if deployment_outputs is not None:
        document = load(deployment_outputs)
        automatic = document["automatic_onboarding_enabled"]
        return {"schema_version": "2.0", "deployment_method": "terraform", "installation_id": document["installation_id"],
            "account_id": document["account_id"], "release_id": document["release_id"], "control_plane_region": document["control_plane_region"],
            "status": "DEPLOYED" if automatic else "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED",
            "automatic_onboarding_enabled": automatic, "admin_bootstrap": "NOT_REQUESTED"}
    require(legacy_path is not None, "INSTALLATION_RESULT_OR_DEPLOYMENT_OUTPUTS_REQUIRED")
    return json.loads(Path(legacy_path).read_text(encoding="utf-8-sig"), object_pairs_hook=_object)
