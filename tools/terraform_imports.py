"""Build a private native-Terraform import manifest from owned CFN snapshots.

This tool does not import, apply, update or delete AWS resources. The only live
calls read STS identity, API/Cognito names and existing Lambda permission SIDs. Output contains
company resource identifiers and must stay outside the public source checkout.
Import formats follow the official hashicorp/aws resource Import sections:
https://github.com/hashicorp/terraform-provider-aws/tree/main/website/docs/r
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from install import cli

# Provider 6.x injects a per-resource region except on global resources. The
# regional import suffix is necessary when the provider default differs from
# the resource's configured region. These sets are reviewed against 6.69's
# provider schema; unknown types require review rather than a guessed scope.
# https://www.hashicorp.com/en/blog/terraform-aws-provider-6-0-now-generally-available
GLOBAL_IMPORT_TYPES = frozenset({"aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment"})
REGIONAL_IMPORT_TYPES = frozenset({
    "aws_kms_key", "aws_s3_bucket", "aws_s3_bucket_versioning", "aws_s3_bucket_ownership_controls", "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_policy", "aws_dynamodb_table",
    "aws_cloudwatch_event_bus", "aws_sns_topic", "aws_sns_topic_policy", "aws_sqs_queue", "aws_sqs_queue_policy", "aws_cloudwatch_log_group",
    "aws_lambda_function", "aws_lambda_permission", "aws_cloudwatch_log_metric_filter", "aws_lambda_function_event_invoke_config",
    "aws_cloudwatch_metric_alarm", "aws_cloudwatch_event_rule", "aws_cloudwatch_event_target", "aws_cognito_user_pool", "aws_cognito_user_group",
    "aws_cognito_user_pool_client", "aws_cognito_user_pool_domain", "aws_apigatewayv2_api", "aws_apigatewayv2_integration", "aws_apigatewayv2_route",
    "aws_apigatewayv2_stage", "aws_lambda_alias", "aws_sfn_state_machine", "aws_lambda_event_source_mapping", "aws_sns_topic_subscription"})


class ImportSpecError(ValueError):
    def __init__(self, code, logical=None):
        super().__init__(code)
        self.code, self.logical = code, logical


def require(test, code, logical=None):
    if not test:
        raise ImportSpecError(code, logical)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def read_json(path):
    data = Path(path).read_bytes()
    require(len(data) <= 8 * 1024 * 1024, "SNAPSHOT_SIZE_LIMIT")
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=strict_object)


def regional_import_id(kind, identifier, region):
    """Qualify a known regional 6.x resource; keep global IAM IDs untouched."""
    require(isinstance(identifier, str) and identifier, "IMPORT_IDENTIFIER_REQUIRED")
    require(isinstance(region, str) and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region), "IMPORT_REGION_REQUIRED")
    if kind in GLOBAL_IMPORT_TYPES:
        return identifier
    require(kind in REGIONAL_IMPORT_TYPES, "UNREVIEWED_IMPORT_REGION_SUPPORT")
    if "@" in identifier:
        original, selected = identifier.rsplit("@", 1)
        require(original and selected == region, "IMPORT_REGION_SUFFIX_MISMATCH")
        return identifier
    return identifier + "@" + region


def function_name(value):
    require(isinstance(value, str), "FUNCTION_IDENTIFIER_REQUIRED")
    if value.startswith("arn:"):
        require(":function:" in value, "FUNCTION_ARN_REQUIRED")
        return value.split(":function:", 1)[1]
    return value


def rule_name(value):
    require(isinstance(value, str), "RULE_IDENTIFIER_REQUIRED")
    if ":rule/" in value:
        return value.rsplit("/", 1)[-1]
    return value.split("|", 1)[-1]


class Snapshot:
    def __init__(self, path, module, *, profile, call):
        self.path, self.module, self.profile, self.call = Path(path), module, profile, call
        document = read_json(path)
        stacks = document.get("stack", {}).get("Stacks", [])
        require(len(stacks) == 1, "EXACT_SNAPSHOT_STACK_REQUIRED")
        self.stack = stacks[0]
        parts = str(self.stack.get("StackId", "")).split(":", 5)
        require(len(parts) == 6 and parts[:3] == ["arn", "aws", "cloudformation"] and re.fullmatch(r"\d{12}", parts[4]), "SNAPSHOT_ACCOUNT_SCOPE_REQUIRED")
        self.region, self.account, self.name = parts[3], parts[4], self.stack["StackName"]
        require(self.stack.get("StackStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE"}, "STABLE_SNAPSHOT_STACK_REQUIRED")
        tags = {row.get("Key"): row.get("Value") for row in self.stack.get("Tags", [])}
        require(tags.get("ManagedBy") == "enterprise-security" and isinstance(tags.get("InstallationId"), str), "OWNED_SNAPSHOT_STACK_REQUIRED")
        self.installation_id = tags["InstallationId"]
        body = document.get("template", {}).get("TemplateBody")
        self.template = json.loads(body, object_pairs_hook=strict_object) if isinstance(body, str) else body
        require(isinstance(self.template, dict) and isinstance(self.template.get("Resources"), dict), "ORIGINAL_TEMPLATE_REQUIRED")
        self.resources = {}
        for row in document.get("resources", {}).get("StackResourceSummaries", []):
            logical = row.get("LogicalResourceId")
            require(isinstance(logical, str) and logical not in self.resources, "EXACT_RESOURCE_IDENTITY_REQUIRED")
            if row.get("ResourceStatus") != "DELETE_COMPLETE":
                require(isinstance(row.get("PhysicalResourceId"), str) and row["PhysicalResourceId"], "RESOURCE_PHYSICAL_ID_REQUIRED", logical)
                self.resources[logical] = row
        self.parameters = {row["ParameterKey"]: row.get("ParameterValue") for row in self.stack.get("Parameters", [])}
        for key, definition in self.template.get("Parameters", {}).items():
            if key not in self.parameters and "Default" in definition:
                self.parameters[key] = definition["Default"]
            if key in self.parameters and definition.get("Type") == "CommaDelimitedList" and isinstance(self.parameters[key], str):
                self.parameters[key] = self.parameters[key].split(",")
        self.metadata_cache = {}

    def aws(self, *arguments):
        require(arguments[:2] in {("cognito-idp", "describe-user-pool"), ("cognito-idp", "describe-user-pool-client"), ("apigatewayv2", "get-api"),
                                 ("lambda", "get-policy")}, "UNSUPPORTED_METADATA_READ")
        return self.call(*arguments, profile=self.profile, region=self.region)

    def props(self, logical):
        require(logical in self.resources and logical in self.template["Resources"], "RESOURCE_NOT_IN_SNAPSHOT_TEMPLATE", logical)
        row, definition = self.resources[logical], self.template["Resources"][logical]
        require(row.get("ResourceType") == definition.get("Type"), "RESOURCE_TYPE_MISMATCH", logical)
        return definition.get("Properties", {})

    def physical(self, logical):
        require(logical in self.resources, "RESOURCE_NOT_PRESENT", logical)
        return self.resources[logical]["PhysicalResourceId"]

    def ref(self, logical):
        pseudo = {"AWS::AccountId": self.account, "AWS::Region": self.region, "AWS::StackName": self.name,
                  "AWS::StackId": self.stack["StackId"], "AWS::Partition": "aws", "AWS::URLSuffix": "amazonaws.com", "AWS::NoValue": None}
        if logical in pseudo:
            return pseudo[logical]
        if logical in self.parameters:
            return self.parameters[logical]
        value = self.physical(logical)
        kind = self.resources[logical]["ResourceType"]
        return rule_name(value) if kind == "AWS::Events::Rule" else value

    def getatt(self, logical, attribute):
        value, props = self.physical(logical), self.props(logical)
        kind = self.resources[logical]["ResourceType"]
        if attribute == "Version" and kind == "AWS::Lambda::Version":
            return value.rsplit(":", 1)[-1]
        if attribute == "Name":
            return self.physical_name(logical)
        if attribute == "Arn":
            if value.startswith("arn:"):
                return value
            prefix = f"arn:aws:{{service}}:{self.region}:{self.account}:"
            if kind == "AWS::IAM::Role":
                path = self.resolve(props.get("Path", "/"))
                return f"arn:aws:iam::{self.account}:role" + path + value
            if kind == "AWS::S3::Bucket": return "arn:aws:s3:::" + value
            if kind == "AWS::Lambda::Function": return prefix.format(service="lambda") + "function:" + value
            if kind == "AWS::SQS::Queue": return prefix.format(service="sqs") + value.rsplit("/", 1)[-1]
            if kind == "AWS::DynamoDB::Table": return prefix.format(service="dynamodb") + "table/" + value
            if kind == "AWS::KMS::Key": return prefix.format(service="kms") + "key/" + value
            if kind == "AWS::Logs::LogGroup": return prefix.format(service="logs") + "log-group:" + value + ":*"
            if kind == "AWS::Events::EventBus": return prefix.format(service="events") + "event-bus/" + value
            if kind == "AWS::Events::Rule":
                bus = self.resolve(props.get("EventBusName", "default"))
                return prefix.format(service="events") + "rule/" + ("" if bus == "default" else bus + "/") + rule_name(value)
            if kind == "AWS::Cognito::UserPool": return prefix.format(service="cognito-idp") + "userpool/" + value
        raise ImportSpecError("UNSUPPORTED_CFN_ATTRIBUTE", logical)

    def condition(self, name):
        require(name in self.template.get("Conditions", {}), "UNKNOWN_CFN_CONDITION")
        return self.resolve(self.template["Conditions"][name])

    def resolve(self, value):
        if isinstance(value, list): return [self.resolve(item) for item in value]
        if not isinstance(value, dict): return value
        if set(value) == {"Ref"}: return self.ref(value["Ref"])
        if set(value) == {"Condition"}: return self.condition(value["Condition"])
        if set(value) == {"Fn::GetAtt"}:
            parts = value["Fn::GetAtt"]
            return self.getatt(*(parts.split(".", 1) if isinstance(parts, str) else parts))
        if set(value) == {"Fn::Sub"}:
            expression = value["Fn::Sub"]
            expression, mapping = (expression, {}) if isinstance(expression, str) else expression
            def replace(match):
                key = match.group(1)
                if key.startswith("!"): return "${" + key[1:] + "}"
                selected = self.resolve(mapping[key]) if key in mapping else self.getatt(*key.split(".", 1)) if "." in key else self.ref(key)
                require(isinstance(selected, (str, int)), "CFN_SUB_SCALAR_REQUIRED")
                return str(selected)
            return re.sub(r"\$\{([^}]+)\}", replace, expression)
        if set(value) == {"Fn::Join"}:
            delimiter, items = value["Fn::Join"]
            return delimiter.join(str(item) for item in self.resolve(items))
        if set(value) == {"Fn::Split"}:
            delimiter, item = value["Fn::Split"]
            return self.resolve(item).split(delimiter)
        if set(value) == {"Fn::Select"}:
            index, items = value["Fn::Select"]
            return self.resolve(items)[int(self.resolve(index))]
        if set(value) == {"Fn::If"}:
            name, yes, no = value["Fn::If"]
            return self.resolve(yes if self.condition(name) else no)
        if set(value) == {"Fn::Equals"}:
            left, right = value["Fn::Equals"]
            return self.resolve(left) == self.resolve(right)
        if set(value) == {"Fn::Not"}: return not self.resolve(value["Fn::Not"][0])
        if set(value) == {"Fn::And"}: return all(self.resolve(item) for item in value["Fn::And"])
        if set(value) == {"Fn::Or"}: return any(self.resolve(item) for item in value["Fn::Or"])
        require(not any(key.startswith("Fn::") for key in value), "UNSUPPORTED_CFN_INTRINSIC")
        return {key: self.resolve(item) for key, item in value.items()}

    def physical_name(self, logical):
        if logical in self.metadata_cache:
            return self.metadata_cache[logical]
        value, props = self.physical(logical), self.props(logical)
        kind = self.resources[logical]["ResourceType"]
        if kind == "AWS::Cognito::UserPool":
            result = self.aws("cognito-idp", "describe-user-pool", "--user-pool-id", value, "--query", "UserPool.{Id:Id,Name:Name}")
            require(result.get("Id") == value and isinstance(result.get("Name"), str), "USER_POOL_NAME_NOT_VERIFIED", logical)
            value = result["Name"]
        elif kind == "AWS::Cognito::UserPoolClient":
            pool = self.resolve(props["UserPoolId"])
            result = self.aws("cognito-idp", "describe-user-pool-client", "--user-pool-id", pool, "--client-id", value,
                              "--query", "UserPoolClient.{UserPoolId:UserPoolId,ClientId:ClientId,ClientName:ClientName}")
            require(result.get("UserPoolId") == pool and result.get("ClientId") == value and isinstance(result.get("ClientName"), str), "USER_POOL_CLIENT_NAME_NOT_VERIFIED", logical)
            value = result["ClientName"]
        elif kind == "AWS::ApiGatewayV2::Api":
            result = self.aws("apigatewayv2", "get-api", "--api-id", value, "--query", "{ApiId:ApiId,Name:Name}")
            require(result.get("ApiId") == value and isinstance(result.get("Name"), str), "API_NAME_NOT_VERIFIED", logical)
            value = result["Name"]
        elif kind == "AWS::SQS::Queue": value = value.rsplit("/", 1)[-1]
        elif kind == "AWS::SNS::Topic": value = value.rsplit(":", 1)[-1]
        elif kind == "AWS::StepFunctions::StateMachine": value = value.rsplit(":", 1)[-1]
        elif kind == "AWS::Events::Rule": value = rule_name(value)
        elif kind == "AWS::Lambda::Function": value = function_name(value)
        self.metadata_cache[logical] = value
        return value

    def import_id(self, logical, native):
        kind, address = native["type"], native["address"]
        value, props = self.physical(logical), self.props(logical)
        cfn = self.resources[logical]["ResourceType"]
        if kind in {"aws_s3_bucket", "aws_s3_bucket_versioning", "aws_s3_bucket_ownership_controls", "aws_s3_bucket_public_access_block",
                    "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_policy"}:
            return value if cfn == "AWS::S3::Bucket" else self.resolve(props["Bucket"])
        if kind in {"aws_kms_key", "aws_dynamodb_table", "aws_cloudwatch_event_bus", "aws_sns_topic", "aws_sqs_queue", "aws_cloudwatch_log_group",
                    "aws_iam_role", "aws_cognito_user_pool", "aws_apigatewayv2_api", "aws_sfn_state_machine", "aws_lambda_event_source_mapping", "aws_sns_topic_subscription"}:
            return value
        if kind == "aws_lambda_function": return function_name(value)
        if kind == "aws_cloudwatch_metric_alarm": return value
        if kind == "aws_sns_topic_policy": return self.resolve(props["Topics"][0]) if cfn == "AWS::SNS::TopicPolicy" else value
        if kind == "aws_sqs_queue_policy":
            queues = self.resolve(props["Queues"])
            require(len(queues) == 1, "MULTI_QUEUE_POLICY_REQUIRES_EXPLICIT_MAPPING", logical)
            return queues[0]
        if kind == "aws_cloudwatch_event_rule":
            bus = self.resolve(props.get("EventBusName", "default"))
            if bus.startswith("arn:"): bus = bus.split("event-bus/", 1)[1]
            return ("" if bus == "default" else bus + "/") + rule_name(value)
        if kind == "aws_cloudwatch_event_target":
            match = re.search(r"_Target(\d+)(?:\[0\])?$", address)
            require(match is not None, "TARGET_INDEX_REQUIRED", logical)
            targets = props.get("Targets", [])
            index = int(match.group(1))
            require(index < len(targets), "TARGET_NOT_IN_SNAPSHOT", logical)
            return self.import_id(logical, {"type": "aws_cloudwatch_event_rule", "address": address}) + "/" + self.resolve(targets[index]["Id"])
        if kind == "aws_iam_role_policy":
            if cfn == "AWS::IAM::Role":
                match = re.search(r"_Inline(\d+)(?:\[0\])?$", address)
                require(match is not None and int(match.group(1)) < len(props.get("Policies", [])), "INLINE_POLICY_INDEX_REQUIRED", logical)
                return value + ":" + self.resolve(props["Policies"][int(match.group(1))]["PolicyName"])
            roles = self.resolve(props.get("Roles", []))
            require(len(roles) == 1, "MULTI_ROLE_POLICY_REQUIRES_EXPLICIT_MAPPING", logical)
            return roles[0] + ":" + self.resolve(props["PolicyName"])
        if kind == "aws_iam_role_policy_attachment":
            match = re.search(r"_(?:Attachment|Managed)(\d+)(?:\[0\])?$", address)
            require(cfn == "AWS::IAM::Role" and match is not None, "MANAGED_POLICY_INDEX_REQUIRED", logical)
            index = int(match.group(1))
            require(index < len(props.get("ManagedPolicyArns", [])), "MANAGED_POLICY_NOT_IN_SNAPSHOT", logical)
            return value + "/" + self.resolve(props["ManagedPolicyArns"][index])
        if kind == "aws_lambda_permission":
            function = function_name(self.resolve(props["FunctionName"]))
            selected = self.aws("lambda", "get-policy", "--function-name", function, "--query", "Policy")
            policy = json.loads(selected, object_pairs_hook=strict_object) if isinstance(selected, str) else selected
            require(isinstance(policy, dict) and len([row for row in policy.get("Statement", []) if row.get("Sid") == value]) == 1,
                    "LAMBDA_PERMISSION_STATEMENT_NOT_VERIFIED", logical)
            return function + "/" + value
        if kind == "aws_lambda_function_event_invoke_config":
            function = function_name(self.resolve(props["FunctionName"]))
            qualifier = self.resolve(props.get("Qualifier", ""))
            return function + (":" + qualifier if qualifier else "")
        if kind == "aws_lambda_alias":
            return function_name(self.resolve(props["FunctionName"])) + "/" + self.resolve(props["Name"])
        if kind == "aws_cloudwatch_log_metric_filter":
            return self.resolve(props["LogGroupName"]) + ":" + value
        if kind == "aws_cognito_user_pool_client": return self.resolve(props["UserPoolId"]) + "/" + value
        if kind == "aws_cognito_user_group": return self.resolve(props["UserPoolId"]) + "/" + self.resolve(props["GroupName"])
        if kind == "aws_cognito_user_pool_domain": return self.resolve(props["Domain"])
        if kind in {"aws_apigatewayv2_integration", "aws_apigatewayv2_route", "aws_apigatewayv2_stage"}:
            return self.resolve(props["ApiId"]) + "/" + (self.resolve(props["StageName"]) if kind == "aws_apigatewayv2_stage" else value)
        raise ImportSpecError("UNSUPPORTED_TERRAFORM_IMPORT_TYPE", logical)


def build(snapshots, *, resource_map=None, profile="default", call=cli):
    resource_map = read_json(resource_map or ROOT / "terraform/resource-map.json")
    require(resource_map.get("provider") == "hashicorp/aws" and resource_map.get("provider_version") == "6.69.0", "REVIEWED_RESOURCE_MAP_REQUIRED")
    result = {"physical_names": {"foundation": {}, "governance": {}, "ingress": {}}, "imports": [], "preserved_versions": []}
    source, expected_account, expected_installation = Path(snapshots), None, None
    addresses, identities = set(), set()
    for module in ("foundation", "governance", "ingress"):
        path = source / (module + "-snapshot.json")
        if not path.exists():
            require(module == "ingress", "REQUIRED_SNAPSHOT_MISSING")
            continue
        snapshot = Snapshot(path, module, profile=profile, call=call)
        if expected_account is None:
            expected_account, expected_installation = snapshot.account, snapshot.installation_id
            identity = call("sts", "get-caller-identity", profile=profile, region=snapshot.region)
            require(identity.get("Account") == expected_account, "WRONG_AWS_ACCOUNT")
        require(snapshot.account == expected_account and snapshot.installation_id == expected_installation, "SNAPSHOT_INSTALLATION_MISMATCH")
        expected_name = expected_installation + ("-governance" if module == "governance" else "-ingress" if module == "ingress" else "")
        require(snapshot.name == expected_name, "SNAPSHOT_STACK_NAME_MISMATCH")
        prefix = "module." + module + ("[" + json.dumps(snapshot.region) + "]" if module == "ingress" else "")
        names = result["physical_names"][module]
        if module == "ingress":
            names = names.setdefault(snapshot.region, {})
        mapping = resource_map.get("modules", {}).get(module, {})
        for logical, deployed in snapshot.resources.items():
            cfn_type = deployed["ResourceType"]
            if cfn_type == "AWS::Lambda::Version":
                result["preserved_versions"].append({"logical": logical, "cfn_type": cfn_type, "physical_id": deployed["PhysicalResourceId"],
                    "module": prefix, "region": snapshot.region, "status": "PRESERVED_NOT_IMPORTED"})
                continue
            require(logical in mapping and mapping[logical].get("cfn_type") == cfn_type, "RESOURCE_NOT_IN_REVIEWED_NATIVE_MAP", logical)
            entry = mapping[logical]
            if entry.get("physical_name_override"):
                names[logical] = snapshot.physical_name(logical)
            natives = entry.get("terraform_imports", [])
            require(natives, "NATIVE_IMPORT_METADATA_REQUIRED", logical)
            for native in natives:
                require(isinstance(native.get("address"), str) and re.fullmatch(r"aws_[a-z0-9_]+\.[A-Za-z][A-Za-z0-9_]*(?:\[0\])?", native["address"]),
                        "EXACT_NATIVE_RESOURCE_ADDRESS_REQUIRED", logical)
                address = prefix + "." + native["address"]
                identifier = regional_import_id(native["type"], snapshot.import_id(logical, native), snapshot.region)
                require(isinstance(identifier, str) and 0 < len(identifier) <= 2048 and "\n" not in identifier and "\r" not in identifier, "BOUNDED_IMPORT_ID_REQUIRED", logical)
                identity = (native["type"], snapshot.region, identifier)
                require(address not in addresses and identity not in identities, "DUPLICATE_NATIVE_RESOURCE_IMPORT", logical)
                addresses.add(address); identities.add(identity)
                result["imports"].append({"address": address, "id": identifier, "logical": logical, "cfn_type": cfn_type, "region": snapshot.region})
    result["imports"].sort(key=lambda row: row["address"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshots", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resource-map", type=Path, default=ROOT / "terraform/resource-map.json")
    parser.add_argument("--profile", default="default")
    args = parser.parse_args(argv)
    try:
        require(not args.output.resolve().is_relative_to(ROOT), "PRIVATE_OUTPUT_MUST_BE_OUTSIDE_PUBLIC_CHECKOUT")
        result = build(args.snapshots, resource_map=args.resource_map, profile=args.profile)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        body = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        args.output.write_bytes(body)
        print(json.dumps({"status": "IMPORT_SPEC_READY", "imports": len(result["imports"]), "preserved_versions": len(result["preserved_versions"]),
                          "manifest_sha256": hashlib.sha256(body).hexdigest(), "aws_mutations": 0}))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, ImportSpecError) else "IMPORT_SPEC_DEPENDENCY_FAILED"
        result = {"status": "REVIEW_REQUIRED", "error_code": code}
        if isinstance(error, ImportSpecError) and error.logical and re.fullmatch(r"[A-Za-z0-9]{1,255}", error.logical):
            result["logical_resource_id"] = error.logical
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
