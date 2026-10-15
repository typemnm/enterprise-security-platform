"""Translate the reviewed platform templates into native AWS Terraform modules.

Development/CI tool only. Enterprise applies consume the committed .tf.json;
they do not run this program or CloudFormation. Unknown properties fail closed.
The provider schema must be obtained from the pinned hashicorp/aws provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MODULES = {"foundation": "foundation.template.json", "ingress": "security-log-ingress.template.json",
           "governance": "control_plane.template.json"}
TYPE_MAP = {
    "AWS::ApiGatewayV2::Api": "aws_apigatewayv2_api",
    "AWS::ApiGatewayV2::Integration": "aws_apigatewayv2_integration",
    "AWS::ApiGatewayV2::Route": "aws_apigatewayv2_route",
    "AWS::ApiGatewayV2::Stage": "aws_apigatewayv2_stage",
    "AWS::CloudWatch::Alarm": "aws_cloudwatch_metric_alarm",
    "AWS::Cognito::UserPool": "aws_cognito_user_pool",
    "AWS::Cognito::UserPoolClient": "aws_cognito_user_pool_client",
    "AWS::Cognito::UserPoolDomain": "aws_cognito_user_pool_domain",
    "AWS::Cognito::UserPoolGroup": "aws_cognito_user_group",
    "AWS::DynamoDB::Table": "aws_dynamodb_table",
    "AWS::Events::EventBus": "aws_cloudwatch_event_bus",
    "AWS::Events::Rule": "aws_cloudwatch_event_rule",
    "AWS::IAM::Policy": "aws_iam_role_policy",
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::KMS::Key": "aws_kms_key",
    "AWS::Lambda::Alias": "aws_lambda_alias",
    "AWS::Lambda::EventInvokeConfig": "aws_lambda_function_event_invoke_config",
    "AWS::Lambda::EventSourceMapping": "aws_lambda_event_source_mapping",
    "AWS::Lambda::Function": "aws_lambda_function",
    "AWS::Lambda::Permission": "aws_lambda_permission",
    "AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
    "AWS::Logs::MetricFilter": "aws_cloudwatch_log_metric_filter",
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::S3::BucketPolicy": "aws_s3_bucket_policy",
    "AWS::SNS::Subscription": "aws_sns_topic_subscription",
    "AWS::SNS::Topic": "aws_sns_topic",
    "AWS::SNS::TopicPolicy": "aws_sns_topic_policy",
    "AWS::SQS::Queue": "aws_sqs_queue",
    "AWS::SQS::QueuePolicy": "aws_sqs_queue_policy",
    "AWS::StepFunctions::StateMachine": "aws_sfn_state_machine",
}
NAME_RULES = {
    "AWS::IAM::Role": ("RoleName", 64), "AWS::Lambda::Function": ("FunctionName", 64),
    "AWS::Events::EventBus": ("Name", 256), "AWS::Events::Rule": ("Name", 64),
    "AWS::SQS::Queue": ("QueueName", 80), "AWS::SNS::Topic": ("TopicName", 256),
    "AWS::Logs::LogGroup": ("LogGroupName", 512), "AWS::DynamoDB::Table": ("TableName", 255),
    "AWS::S3::Bucket": ("BucketName", 63), "AWS::Cognito::UserPool": ("UserPoolName", 128),
    "AWS::Cognito::UserPoolClient": ("ClientName", 128),
    "AWS::ApiGatewayV2::Api": ("Name", 128), "AWS::CloudWatch::Alarm": ("AlarmName", 255),
    "AWS::StepFunctions::StateMachine": ("StateMachineName", 80),
    "AWS::Logs::MetricFilter": ("FilterName", 512),
}
PHYSICAL_NAME_OVERRIDES = set(NAME_RULES) | {"AWS::Lambda::Permission"}


def q(value):
    """A literal HCL string, with Terraform interpolation kept literal."""
    return json.dumps(str(value).replace("${", "$${").replace("%{", "%%{"), ensure_ascii=False)


def tf(expression):
    return "${" + expression + "}"


def refs(value):
    found = set()
    if isinstance(value, dict):
        if set(value) == {"Ref"}: found.add(value["Ref"])
        if "Fn::GetAtt" in value:
            v = value["Fn::GetAtt"]
            found.add(v.split(".", 1)[0] if isinstance(v, str) else v[0])
        if "Fn::Sub" in value:
            text = value["Fn::Sub"]
            text = text[0] if isinstance(text, list) else text
            found.update(x.split(".", 1)[0] for x in re.findall(r"\$\{([^!][^}]*)\}", text))
        for x in value.values(): found.update(refs(x))
    elif isinstance(value, list):
        for x in value: found.update(refs(x))
    return found


class Converter:
    def __init__(self, module, template, schemas):
        self.module, self.template, self.schemas = module, template, schemas
        self.cfn = template["Resources"]
        self.resources, self.mapping = {}, {}
        self.locals = {}
        self.virtual_versions = {key: r["Properties"]["FunctionName"]["Ref"] for key, r in self.cfn.items()
                                 if r["Type"] == "AWS::Lambda::Version"}
        self.primary = {key: (TYPE_MAP[r["Type"]] + "." + key) for key, r in self.cfn.items()
                        if r["Type"] != "AWS::Lambda::Version"}
        for key, function in self.virtual_versions.items(): self.primary[key] = self.primary[function]
        self.defaults = {key: p["Default"] for key, p in template["Parameters"].items() if "Default" in p}
        raw = "merge(" + self.expr(self.defaults) + ", var.parameters)"
        self.locals["raw_parameters"] = tf(raw)
        params = []
        for key, p in template["Parameters"].items():
            value = "local.raw_parameters[" + q(key) + "]"
            if p["Type"] == "Number": value = "tonumber(" + value + ")"
            if p["Type"] == "CommaDelimitedList": value = "try(tolist(" + value + "), split(\",\", tostring(" + value + ")))"
            params.append(q(key) + " = " + value)
        self.locals["parameters"] = tf("{" + ", ".join(params) + "}")
        for key, r in self.cfn.items():
            if r["Type"] in NAME_RULES: self.make_name(key, r)
        for key, value in template.get("Conditions", {}).items():
            self.locals["condition_" + key] = tf(self.expr(value))

    def make_name(self, key, resource):
        prop, limit = NAME_RULES[resource["Type"]]
        explicit = resource.get("Properties", {}).get(prop)
        if explicit is not None:
            base = self.expr(explicit)
        else:
            pieces = ["var.stack_name"]
            if resource["Type"] == "AWS::IAM::Role": pieces.append("var.region")
            if resource["Type"] == "AWS::S3::Bucket": pieces += ["var.account_id", "var.region"]
            pieces.append(q(key.lower()))
            base = "join(\"-\", [" + ", ".join(pieces) + "])"
        # Migration overrides are never normalized or truncated.
        shortened = f"length({base}) <= {limit} ? {base} : format(\"%s-%s\", substr({base}, 0, {limit - 9}), substr(sha256({base}), 0, 8))"
        self.locals["name_" + key] = tf("lookup(var.physical_names, " + q(key) + ", " + shortened + ")" if resource["Type"] in PHYSICAL_NAME_OVERRIDES else shortened)

    def name(self, key): return "local.name_" + key

    def address(self, key):
        result = self.primary[key]
        if self.cfn[key].get("Condition"): result += "[0]"
        return result

    def expected_arn(self, key):
        kind = self.cfn[key]["Type"]
        name = self.name(key)
        prefix = "format(\"arn:%s:"
        partition = "data.aws_partition.current.partition"
        if kind == "AWS::Lambda::Function":
            return f'{prefix}lambda:%s:%s:function:%s\", {partition}, var.region, var.account_id, {name})'
        if kind == "AWS::IAM::Role": return f'{prefix}iam::%s:role/%s\", {partition}, var.account_id, {name})'
        if kind == "AWS::Events::EventBus": return f'{prefix}events:%s:%s:event-bus/%s\", {partition}, var.region, var.account_id, {name})'
        if kind == "AWS::Events::Rule":
            bus = self.cfn[key]["Properties"].get("EventBusName", "default")
            segment = self.expr(bus)
            path = f'({segment} == \"default\" ? {name} : join(\"/\", [{segment}, {name}]))'
            return f'{prefix}events:%s:%s:rule/%s\", {partition}, var.region, var.account_id, {path})'
        if kind == "AWS::Logs::LogGroup":
            return f'{prefix}logs:%s:%s:log-group:%s:*\", {partition}, var.region, var.account_id, {name})'
        if kind == "AWS::DynamoDB::Table":
            return f'{prefix}dynamodb:%s:%s:table/%s\", {partition}, var.region, var.account_id, {name})'
        if kind == "AWS::StepFunctions::StateMachine":
            return f'{prefix}states:%s:%s:stateMachine:%s\", {partition}, var.region, var.account_id, {name})'
        return self.address(key) + ".arn"

    def declared_arn(self, text):
        """Keep scoped ARN conditions aligned with bounded/migrated names.

        The source ASL uses deterministic ARN strings to break IAM/Lambda/SFN
        cycles. Terraform must preserve that technique while honoring overrides.
        """
        prefixes = {
            "AWS::Lambda::Function": "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:",
            "AWS::IAM::Role": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/",
            "AWS::StepFunctions::StateMachine": "arn:${AWS::Partition}:states:${AWS::Region}:${AWS::AccountId}:stateMachine:",
        }
        for logical, resource in self.cfn.items():
            kind = resource["Type"]
            if kind not in prefixes: continue
            prop = NAME_RULES[kind][0]
            declared = resource["Properties"].get(prop)
            if not isinstance(declared, dict) or set(declared) != {"Fn::Sub"} or not isinstance(declared["Fn::Sub"], str): continue
            if text == prefixes[kind] + declared["Fn::Sub"]:
                return self.expected_arn(logical)
            if kind == "AWS::StepFunctions::StateMachine":
                execution = prefixes[kind].replace(":stateMachine:", ":execution:") + declared["Fn::Sub"]
                if text.startswith(execution + ":"):
                    suffix = text[len(execution):]
                    if "${" not in suffix:
                        return ('format("arn:%s:states:%s:%s:execution:%s%s", data.aws_partition.current.partition, '
                                'var.region, var.account_id, ' + self.name(logical) + ", " + q(suffix) + ")")
        return None

    def ref(self, key):
        pseudo = {"AWS::AccountId": "var.account_id", "AWS::Region": "var.region", "AWS::StackName": "var.stack_name",
                  "AWS::Partition": "data.aws_partition.current.partition", "AWS::URLSuffix": "data.aws_partition.current.dns_suffix",
                  "AWS::NoValue": "null"}
        if key in pseudo: return pseudo[key]
        if key in self.template["Parameters"]: return "local.parameters[" + q(key) + "]"
        if key in self.virtual_versions: return self.address(key) + ".version"
        kind = self.cfn[key]["Type"]
        if kind in ["AWS::IAM::Role", "AWS::Lambda::Function", "AWS::Events::EventBus", "AWS::Events::Rule", "AWS::Logs::LogGroup", "AWS::DynamoDB::Table", "AWS::CloudWatch::Alarm"]:
            return self.name(key)
        if kind in ["AWS::SNS::Topic", "AWS::Lambda::Alias", "AWS::StepFunctions::StateMachine"]: return self.address(key) + ".arn"
        if kind == "AWS::SQS::Queue": return self.address(key) + ".url"
        return self.address(key) + ".id"

    def getatt(self, key, attribute):
        if key in self.virtual_versions and attribute == "Version": return self.address(key) + ".version"
        if attribute == "Arn": return self.expected_arn(key)
        kind = self.cfn[key]["Type"]
        aliases = {"QueueName": "name", "StreamArn": "stream_arn", "DomainName": "bucket_domain_name",
                   "RegionalDomainName": "bucket_regional_domain_name", "ApiEndpoint": "api_endpoint",
                   "Version": "version", "ClientId": "id"}
        if kind == "AWS::SQS::Queue" and attribute == "QueueName": return self.name(key)
        if attribute not in aliases: raise ValueError(f"Unsupported GetAtt {key}.{attribute}")
        return self.address(key) + "." + aliases[attribute]

    def expr(self, value):
        if value is None: return "null"
        if isinstance(value, bool): return str(value).lower()
        if isinstance(value, (int, float)): return str(value)
        if isinstance(value, str): return q(value)
        if isinstance(value, list):
            # AWS::NoValue list elements are omitted, including conditional IAM statements.
            raw = "[" + ", ".join(self.expr(x) for x in value) + "]"
            if any("AWS::NoValue" in str(x) for x in value): return "[for item in " + raw + " : item if item != null]"
            return raw
        if set(value) == {"Ref"}: return self.ref(value["Ref"])
        if set(value) == {"Condition"}: return "local.condition_" + value["Condition"]
        if "Fn::GetAtt" in value:
            pair = value["Fn::GetAtt"]
            pair = pair.split(".", 1) if isinstance(pair, str) else pair
            return self.getatt(*pair)
        if "Fn::Sub" in value:
            spec = value["Fn::Sub"]
            text, variables = (spec, {}) if isinstance(spec, str) else spec
            known_arn = self.declared_arn(text) if not variables else None
            if known_arn is not None: return known_arn
            pieces, pos = [], 0
            for match in re.finditer(r"\$\{([^}]+)\}", text):
                if match.start() > pos: pieces.append(q(text[pos:match.start()]))
                token = match[1]
                if token.startswith("!"): pieces.append(q("${" + token[1:] + "}"))
                elif token in variables: pieces.append(self.expr(variables[token]))
                elif "." in token: pieces.append(self.getatt(*token.split(".", 1)))
                else: pieces.append(self.ref(token))
                pos = match.end()
            if pos < len(text): pieces.append(q(text[pos:]))
            return 'join("", [' + ", ".join(pieces) + "])"
        if "Fn::Join" in value:
            sep, items = value["Fn::Join"]
            return "join(" + self.expr(sep) + ", " + self.expr(items) + ")"
        if "Fn::Split" in value:
            sep, text = value["Fn::Split"]
            return "split(" + self.expr(sep) + ", " + self.expr(text) + ")"
        if "Fn::Select" in value:
            index, items = value["Fn::Select"]
            return "(" + self.expr(items) + ")[" + self.expr(index) + "]"
        if "Fn::If" in value:
            condition, yes, no = value["Fn::If"]
            return "(local.condition_" + condition + " ? " + self.expr(yes) + " : " + self.expr(no) + ")"
        if "Fn::Equals" in value:
            a, b = value["Fn::Equals"]
            return "(" + self.expr(a) + " == " + self.expr(b) + ")"
        if "Fn::Not" in value: return "!(" + self.expr(value["Fn::Not"][0]) + ")"
        for key, operator in [("Fn::And", " && "), ("Fn::Or", " || ")]:
            if key in value: return "(" + operator.join(self.expr(x) for x in value[key]) + ")"
        if any(k.startswith("Fn::") for k in value): raise ValueError("Unsupported intrinsic: " + str(list(value)))
        return "{" + ", ".join(q(k) + " = " + self.expr(v) for k, v in value.items()) + "}"

    def value(self, value): return tf(self.expr(value))
    def json(self, value): return tf("jsonencode(" + self.expr(value) + ")")

    def tags(self, value):
        if isinstance(value, list): value = {x["Key"]: x["Value"] for x in value}
        return tf("merge(" + self.expr(value or {}) + ', {ManagedBy = "enterprise-security", InstallationId = var.installation_id})')

    def add(self, logical, tf_type, properties, *, suffix="", dependencies=(), condition=None, retain=None):
        label = logical + suffix
        address = tf_type + "." + label
        schema = self.schemas[tf_type]["block"]
        if "region" in schema.get("attributes", {}): properties["region"] = "${var.region}"
        if "tags" in schema.get("attributes", {}) and "tags" not in properties: properties["tags"] = self.tags({})
        selected_condition = condition or self.cfn[logical].get("Condition")
        if selected_condition: properties["count"] = "${local.condition_" + selected_condition + " ? 1 : 0}"
        dependencies = set(dependencies) | {self.primary[x] for x in self.cfn[logical].get("DependsOn", []) if x in self.primary}
        dependencies.discard(address)
        if dependencies: properties["depends_on"] = sorted(dependencies)
        if retain is None: retain = self.cfn[logical].get("DeletionPolicy") == "Retain"
        if retain: properties.setdefault("lifecycle", {})["prevent_destroy"] = True
        self.validate_block(address, properties, schema)
        self.resources.setdefault(tf_type, {})[label] = properties
        self.mapping.setdefault(logical, {"cfn_type": self.cfn[logical]["Type"], "condition": self.cfn[logical].get("Condition"),
                                         "resources": [], "physical_name_override": self.cfn[logical]["Type"] in PHYSICAL_NAME_OVERRIDES})["resources"].append(address)
        return address

    def validate_block(self, address, properties, schema):
        meta = {"count", "for_each", "depends_on", "lifecycle", "provider"}
        unknown = set(properties) - set(schema.get("attributes", {})) - set(schema.get("block_types", {})) - meta
        if unknown: raise ValueError(f"Provider schema rejects {address}: {sorted(unknown)}")
        missing = {key for key, val in schema.get("attributes", {}).items() if val.get("required")} - set(properties)
        if missing: raise ValueError(f"Required provider attributes absent {address}: {sorted(missing)}")
        for key, value in properties.items():
            if key not in schema.get("block_types", {}): continue
            shape = schema["block_types"][key]
            if isinstance(value, list):
                for item in value: self.validate_block(address + "." + key, item, shape["block"])
            elif isinstance(value, dict): self.validate_block(address + "." + key, value, shape["block"])

    def copy(self, properties, mapping):
        return {target: self.value(properties[source]) for source, target in mapping.items() if source in properties}

    def ensure_known(self, logical, properties, allowed):
        unknown = set(properties) - set(allowed)
        if unknown: raise ValueError(f"Unmapped CFN properties {logical}: {sorted(unknown)}")

    def dep_refs(self, value, kinds=None):
        return {self.primary[x] for x in refs(value) if x in self.cfn and (kinds is None or self.cfn[x]["Type"] in kinds)}

    def convert(self):
        for key, resource in self.cfn.items():
            if resource["Type"] == "AWS::Lambda::Version":
                self.mapping[key] = {"cfn_type": resource["Type"], "resources": [], "virtual": self.primary[key] + ".version",
                                     "migration": "Do not import/delete existing immutable Lambda versions. Import the function and alias; publish=true updates the alias to the provider-published version only after a reviewed code/configuration change."}
                continue
            handler = getattr(self, "convert_" + resource["Type"].split("::")[-1].lower(), None)
            group = resource["Type"].split("::")[1]
            if group == "IAM": handler = self.convert_iam
            elif group == "Lambda": handler = self.convert_lambda
            elif group == "S3": handler = self.convert_s3
            elif group == "SNS": handler = self.convert_sns
            elif group == "SQS": handler = self.convert_sqs
            elif group == "Events": handler = self.convert_events
            elif group == "Cognito": handler = self.convert_cognito
            elif group == "ApiGatewayV2": handler = self.convert_api
            elif group == "Logs": handler = self.convert_logs
            if handler is None: raise ValueError("No native translator for " + resource["Type"])
            handler(key, resource)
        self.add_implicit_dependencies()
        return self.documents()

    def convert_iam(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::IAM::Role":
            self.ensure_known(key, p, ["RoleName", "AssumeRolePolicyDocument", "Policies", "Tags"])
            self.add(key, "aws_iam_role", {"name": tf(self.name(key)), "assume_role_policy": self.json(p["AssumeRolePolicyDocument"]),
                                          "tags": self.tags(p.get("Tags"))})
            for index, policy in enumerate(p.get("Policies", [])):
                self.add(key, "aws_iam_role_policy", {"name": self.value(policy["PolicyName"]),
                    "role": tf(self.address(key) + ".name"), "policy": self.json(policy["PolicyDocument"])}, suffix=f"_Inline{index}", retain=False)
        else:
            self.ensure_known(key, p, ["PolicyName", "PolicyDocument", "Roles"])
            if len(p["Roles"]) != 1: raise ValueError("Separate IAM policy ownership required for multiple roles: " + key)
            self.add(key, "aws_iam_role_policy", {"name": self.value(p["PolicyName"]), "role": self.value(p["Roles"][0]),
                    "policy": self.json(p["PolicyDocument"])}, dependencies=self.dep_refs(p["Roles"]))

    def convert_lambda(self, key, r):
        p, kind = r["Properties"], r["Type"]
        if kind == "AWS::Lambda::Function":
            self.ensure_known(key, p, ["FunctionName", "Runtime", "Handler", "Timeout", "MemorySize", "Role", "Code", "LoggingConfig", "Environment", "Tags", "ReservedConcurrentExecutions", "Description"])
            body = self.copy(p, {"Runtime": "runtime", "Handler": "handler", "Timeout": "timeout", "MemorySize": "memory_size", "Role": "role", "ReservedConcurrentExecutions": "reserved_concurrent_executions", "Description": "description"})
            body.update(function_name=tf(self.name(key)), publish=True, tags=self.tags(p.get("Tags")))
            body.update(self.copy(p["Code"], {"S3Bucket": "s3_bucket", "S3Key": "s3_key", "S3ObjectVersion": "s3_object_version"}))
            version_key = next((k for k, function in self.virtual_versions.items() if function == key), None)
            if version_key: body["source_code_hash"] = self.value(self.cfn[version_key]["Properties"]["CodeSha256"])
            if "Environment" in p:
                # Use one expression for the deployed map and its hard quota
                # check. Terraform length(string) counts Unicode characters,
                # whereas Lambda applies its limit to UTF-8 bytes.
                environment = "environment_" + key
                self.locals[environment] = self.value(p["Environment"]["Variables"])
                body["environment"] = [{"variables": tf("local." + environment)}]
                encoded = "base64encode(jsonencode(local." + environment + "))"
                byte_length = "length(" + encoded + ") * 3 / 4 - length(regexall(\"=\", " + encoded + "))"
                body["lifecycle"] = {"precondition": [{
                    "condition": tf(byte_length + " <= 4096"),
                    "error_message": "Lambda UTF-8 environment JSON exceeds 4096 bytes; reduce exclusions, regions or configured names."
                }]}
            if "LoggingConfig" in p: body["logging_config"] = [self.copy(p["LoggingConfig"], {"LogGroup": "log_group", "LogFormat": "log_format"})]
            self.add(key, TYPE_MAP[kind], body, dependencies=self.dep_refs({"Role": p["Role"], "Logging": p.get("LoggingConfig")}))
        elif kind == "AWS::Lambda::Alias":
            self.ensure_known(key, p, ["FunctionName", "FunctionVersion", "Name"])
            self.add(key, TYPE_MAP[kind], self.copy(p, {"FunctionName": "function_name", "FunctionVersion": "function_version", "Name": "name"}), dependencies=self.dep_refs(p))
        elif kind == "AWS::Lambda::Permission":
            self.ensure_known(key, p, ["Action", "FunctionName", "Principal", "SourceAccount", "SourceArn"])
            body = self.copy(p, {"Action": "action", "FunctionName": "function_name", "Principal": "principal", "SourceAccount": "source_account", "SourceArn": "source_arn"})
            function = p["FunctionName"]
            alias = function.get("Ref") if isinstance(function, dict) else None
            if alias in self.cfn and self.cfn[alias]["Type"] == "AWS::Lambda::Alias":
                # AWS imports permissions as base function name plus qualifier.
                # Keep that canonical form to avoid replacing an unchanged grant.
                alias_properties = self.cfn[alias]["Properties"]
                body["function_name"] = self.value(alias_properties["FunctionName"])
                body["qualifier"] = self.value(alias_properties["Name"])
            body["statement_id"] = tf("lookup(var.physical_names, " + q(key) + ", " + q(key) + ")")
            self.add(key, TYPE_MAP[kind], body, dependencies=self.dep_refs(p["FunctionName"]))
        elif kind == "AWS::Lambda::EventInvokeConfig":
            self.ensure_known(key, p, ["FunctionName", "Qualifier", "MaximumRetryAttempts", "MaximumEventAgeInSeconds", "DestinationConfig"])
            body = self.copy(p, {"FunctionName": "function_name", "Qualifier": "qualifier", "MaximumRetryAttempts": "maximum_retry_attempts", "MaximumEventAgeInSeconds": "maximum_event_age_in_seconds"})
            if "DestinationConfig" in p:
                body["destination_config"] = [{"on_failure": [{"destination": self.value(p["DestinationConfig"]["OnFailure"]["Destination"])}]}]
            self.add(key, TYPE_MAP[kind], body, dependencies=self.dep_refs(p))
        elif kind == "AWS::Lambda::EventSourceMapping":
            mapping = {"FunctionName": "function_name", "EventSourceArn": "event_source_arn", "StartingPosition": "starting_position", "BatchSize": "batch_size", "BisectBatchOnFunctionError": "bisect_batch_on_function_error", "MaximumRetryAttempts": "maximum_retry_attempts", "MaximumRecordAgeInSeconds": "maximum_record_age_in_seconds", "FunctionResponseTypes": "function_response_types", "Enabled": "enabled"}
            self.ensure_known(key, p, list(mapping) + ["DestinationConfig", "FilterCriteria"])
            body = self.copy(p, mapping)
            if "DestinationConfig" in p: body["destination_config"] = [{"on_failure": [{"destination_arn": self.value(p["DestinationConfig"]["OnFailure"]["Destination"])}]}]
            if "FilterCriteria" in p: body["filter_criteria"] = [{"filter": [{"pattern": self.value(x["Pattern"])} for x in p["FilterCriteria"]["Filters"]]}]
            self.add(key, TYPE_MAP[kind], body, dependencies=self.dep_refs(p))

    def convert_events(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::Events::EventBus":
            self.ensure_known(key, p, ["Name", "Tags"])
            self.add(key, TYPE_MAP[r["Type"]], {"name": tf(self.name(key)), "tags": self.tags(p.get("Tags"))})
            return
        self.ensure_known(key, p, ["Name", "State", "EventBusName", "EventPattern", "ScheduleExpression", "Targets"])
        body = self.copy(p, {"EventBusName": "event_bus_name", "ScheduleExpression": "schedule_expression", "State": "state"})
        body["name"] = tf(self.name(key))
        if "EventPattern" in p: body["event_pattern"] = self.json(p["EventPattern"])
        self.add(key, TYPE_MAP[r["Type"]], body, dependencies=self.dep_refs(p.get("EventBusName")))
        for index, target in enumerate(p.get("Targets", [])):
            allowed = ["Id", "Arn", "RoleArn", "Input", "InputTransformer", "RetryPolicy", "DeadLetterConfig"]
            self.ensure_known(key, target, allowed)
            item = self.copy(target, {"Id": "target_id", "Arn": "arn", "RoleArn": "role_arn", "Input": "input"})
            item["rule"] = tf(self.address(key) + ".name")
            if "EventBusName" in p: item["event_bus_name"] = self.value(p["EventBusName"])
            if "RetryPolicy" in target: item["retry_policy"] = [self.copy(target["RetryPolicy"], {"MaximumRetryAttempts": "maximum_retry_attempts", "MaximumEventAgeInSeconds": "maximum_event_age_in_seconds"})]
            if "DeadLetterConfig" in target: item["dead_letter_config"] = [{"arn": self.value(target["DeadLetterConfig"]["Arn"])}]
            if "InputTransformer" in target: item["input_transformer"] = [self.copy(target["InputTransformer"], {"InputPathsMap": "input_paths", "InputTemplate": "input_template"})]
            self.add(key, "aws_cloudwatch_event_target", item, suffix=f"_Target{index}", dependencies=self.dep_refs(target) | {self.primary[key]}, retain=False)

    def convert_sqs(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::SQS::Queue":
            mapping = {"KmsMasterKeyId": "kms_master_key_id", "MessageRetentionPeriod": "message_retention_seconds", "VisibilityTimeout": "visibility_timeout_seconds", "MaximumMessageSize": "max_message_size", "SqsManagedSseEnabled": "sqs_managed_sse_enabled"}
            self.ensure_known(key, p, list(mapping) + ["QueueName", "RedrivePolicy", "Tags"])
            body = self.copy(p, mapping)
            # The native provider historically defaults to 256 KiB; current SQS
            # queues created without this CFN property use the 1 MiB API default.
            if "MaximumMessageSize" not in p: body["max_message_size"] = 1048576
            body.update(name=tf(self.name(key)), tags=self.tags(p.get("Tags")))
            if "RedrivePolicy" in p: body["redrive_policy"] = self.json(p["RedrivePolicy"])
            self.add(key, TYPE_MAP[r["Type"]], body)
        else:
            self.ensure_known(key, p, ["PolicyDocument", "Queues"])
            if len(p["Queues"]) != 1: raise ValueError("A queue policy must own exactly one queue: " + key)
            self.add(key, TYPE_MAP[r["Type"]], {"queue_url": self.value(p["Queues"][0]), "policy": self.json(p["PolicyDocument"])})

    def convert_sns(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::SNS::Topic":
            self.ensure_known(key, p, ["TopicName", "KmsMasterKeyId", "Tags"])
            self.add(key, TYPE_MAP[r["Type"]], {"name": tf(self.name(key)), "kms_master_key_id": self.value(p["KmsMasterKeyId"]), "tags": self.tags(p.get("Tags"))})
        elif r["Type"] == "AWS::SNS::TopicPolicy":
            self.ensure_known(key, p, ["Topics", "PolicyDocument"])
            if len(p["Topics"]) != 1: raise ValueError("A topic policy must own exactly one topic: " + key)
            self.add(key, TYPE_MAP[r["Type"]], {"arn": self.value(p["Topics"][0]), "policy": self.json(p["PolicyDocument"])})
        else:
            self.ensure_known(key, p, ["Endpoint", "Protocol", "TopicArn"])
            self.add(key, TYPE_MAP[r["Type"]], self.copy(p, {"Endpoint": "endpoint", "Protocol": "protocol", "TopicArn": "topic_arn"}))

    def convert_key(self, key, r):
        p = r["Properties"]
        self.ensure_known(key, p, ["EnableKeyRotation", "PendingWindowInDays", "KeyPolicy", "Tags"])
        body = self.copy(p, {"EnableKeyRotation": "enable_key_rotation", "PendingWindowInDays": "deletion_window_in_days"})
        body.update(policy=self.json(p["KeyPolicy"]), tags=self.tags(p.get("Tags")))
        self.add(key, TYPE_MAP[r["Type"]], body)

    def convert_logs(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::Logs::LogGroup":
            self.ensure_known(key, p, ["LogGroupName", "RetentionInDays", "Tags"])
            self.add(key, TYPE_MAP[r["Type"]], {"name": tf(self.name(key)), "retention_in_days": self.value(p["RetentionInDays"]), "tags": self.tags(p.get("Tags"))})
        else:
            self.ensure_known(key, p, ["FilterName", "FilterPattern", "LogGroupName", "MetricTransformations"])
            body = self.copy(p, {"FilterPattern": "pattern", "LogGroupName": "log_group_name"})
            body["name"] = tf(self.name(key))
            transformations = []
            for x in p["MetricTransformations"]:
                item = self.copy(x, {"MetricName": "name", "MetricNamespace": "namespace", "MetricValue": "value", "DefaultValue": "default_value", "Unit": "unit"})
                if "Dimensions" in x:
                    item["dimensions"] = self.value({v["Key"]: v["Value"] for v in x["Dimensions"]})
                transformations.append(item)
            body["metric_transformation"] = transformations
            self.add(key, TYPE_MAP[r["Type"]], body, dependencies=self.dep_refs(p["LogGroupName"]))

    def convert_alarm(self, key, r):
        p = r["Properties"]
        mapping = {"AlarmDescription": "alarm_description", "ComparisonOperator": "comparison_operator", "DatapointsToAlarm": "datapoints_to_alarm", "EvaluationPeriods": "evaluation_periods", "MetricName": "metric_name", "Namespace": "namespace", "Period": "period", "Statistic": "statistic", "Threshold": "threshold", "TreatMissingData": "treat_missing_data", "AlarmActions": "alarm_actions", "OKActions": "ok_actions"}
        self.ensure_known(key, p, list(mapping) + ["AlarmName", "Dimensions", "Metrics", "Tags"])
        body = self.copy(p, mapping)
        body.update(alarm_name=tf(self.name(key)), tags=self.tags(p.get("Tags")))
        if "Dimensions" in p: body["dimensions"] = self.value({x["Name"]: x["Value"] for x in p["Dimensions"]})
        if "Metrics" in p:
            queries = []
            for item in p["Metrics"]:
                query = self.copy(item, {"Id": "id", "Expression": "expression", "ReturnData": "return_data", "Label": "label"})
                if "MetricStat" in item:
                    stat = item["MetricStat"]; metric = stat["Metric"]
                    m = self.copy(stat, {"Period": "period", "Stat": "stat", "Unit": "unit"})
                    m.update(self.copy(metric, {"Namespace": "namespace", "MetricName": "metric_name"}))
                    if "Dimensions" in metric: m["dimensions"] = self.value({x["Name"]: x["Value"] for x in metric["Dimensions"]})
                    query["metric"] = [m]
                queries.append(query)
            body["metric_query"] = queries
        self.add(key, TYPE_MAP[r["Type"]], body)

    def convert_table(self, key, r):
        p = r["Properties"]
        self.ensure_known(key, p, ["TableName", "BillingMode", "DeletionProtectionEnabled", "AttributeDefinitions", "KeySchema", "PointInTimeRecoverySpecification", "SSESpecification", "Tags", "GlobalSecondaryIndexes", "StreamSpecification", "TimeToLiveSpecification"])
        body = self.copy(p, {"BillingMode": "billing_mode", "DeletionProtectionEnabled": "deletion_protection_enabled"})
        body.update(name=tf(self.name(key)), tags=self.tags(p.get("Tags")))
        body["attribute"] = [self.copy(x, {"AttributeName": "name", "AttributeType": "type"}) for x in p["AttributeDefinitions"]]
        for item in p["KeySchema"]: body["hash_key" if item["KeyType"] == "HASH" else "range_key"] = self.value(item["AttributeName"])
        body["point_in_time_recovery"] = [{"enabled": self.value(p["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"])}]
        body["server_side_encryption"] = [{"enabled": self.value(p["SSESpecification"]["SSEEnabled"])}]
        if "StreamSpecification" in p:
            body.update(stream_enabled=True, stream_view_type=self.value(p["StreamSpecification"]["StreamViewType"]))
        if "TimeToLiveSpecification" in p: body["ttl"] = [self.copy(p["TimeToLiveSpecification"], {"AttributeName": "attribute_name", "Enabled": "enabled"})]
        if "GlobalSecondaryIndexes" in p:
            indices = []
            for x in p["GlobalSecondaryIndexes"]:
                item = {"name": self.value(x["IndexName"]), "projection_type": self.value(x["Projection"]["ProjectionType"])}
                item["key_schema"] = [self.copy(part, {"AttributeName": "attribute_name", "KeyType": "key_type"}) for part in x["KeySchema"]]
                indices.append(item)
            body["global_secondary_index"] = indices
        self.add(key, TYPE_MAP[r["Type"]], body)

    def convert_s3(self, key, r):
        p = r["Properties"]
        if r["Type"] == "AWS::S3::BucketPolicy":
            self.ensure_known(key, p, ["Bucket", "PolicyDocument"])
            self.add(key, TYPE_MAP[r["Type"]], {"bucket": self.value(p["Bucket"]), "policy": self.json(p["PolicyDocument"])})
            return
        self.ensure_known(key, p, ["BucketName", "BucketEncryption", "LifecycleConfiguration", "OwnershipControls", "PublicAccessBlockConfiguration", "Tags", "VersioningConfiguration"])
        self.add(key, "aws_s3_bucket", {"bucket": tf(self.name(key)), "force_destroy": False, "tags": self.tags(p.get("Tags"))})
        shared = {"bucket": tf(self.address(key) + ".id")}
        if "VersioningConfiguration" in p: self.add(key, "aws_s3_bucket_versioning", {**shared, "versioning_configuration": [self.copy(p["VersioningConfiguration"], {"Status": "status"})]}, suffix="_Versioning")
        if "OwnershipControls" in p: self.add(key, "aws_s3_bucket_ownership_controls", {"bucket": shared["bucket"], "rule": [self.copy(x, {"ObjectOwnership": "object_ownership"}) for x in p["OwnershipControls"]["Rules"]]}, suffix="_Ownership")
        if "PublicAccessBlockConfiguration" in p:
            self.add(key, "aws_s3_bucket_public_access_block", {"bucket": shared["bucket"], **self.copy(p["PublicAccessBlockConfiguration"], {"BlockPublicAcls": "block_public_acls", "IgnorePublicAcls": "ignore_public_acls", "BlockPublicPolicy": "block_public_policy", "RestrictPublicBuckets": "restrict_public_buckets"})}, suffix="_PublicAccess")
        if "BucketEncryption" in p:
            rules = []
            for x in p["BucketEncryption"]["ServerSideEncryptionConfiguration"]:
                item = self.copy(x, {"BucketKeyEnabled": "bucket_key_enabled"})
                item["apply_server_side_encryption_by_default"] = [self.copy(x["ServerSideEncryptionByDefault"], {"SSEAlgorithm": "sse_algorithm", "KMSMasterKeyID": "kms_master_key_id"})]
                rules.append(item)
            self.add(key, "aws_s3_bucket_server_side_encryption_configuration", {**shared, "rule": rules}, suffix="_Encryption")
        if "LifecycleConfiguration" in p:
            rules = []
            for x in p["LifecycleConfiguration"]["Rules"]:
                self.ensure_known(key, x, ["Id", "Status", "ExpirationInDays", "NoncurrentVersionExpiration", "AbortIncompleteMultipartUpload"])
                item = self.copy(x, {"Id": "id", "Status": "status"})
                item["filter"] = [{"prefix": ""}]
                if "ExpirationInDays" in x: item["expiration"] = [{"days": self.value(x["ExpirationInDays"])}]
                if "NoncurrentVersionExpiration" in x: item["noncurrent_version_expiration"] = [self.copy(x["NoncurrentVersionExpiration"], {"NoncurrentDays": "noncurrent_days"})]
                if "AbortIncompleteMultipartUpload" in x: item["abort_incomplete_multipart_upload"] = [self.copy(x["AbortIncompleteMultipartUpload"], {"DaysAfterInitiation": "days_after_initiation"})]
                rules.append(item)
            dependencies = {"aws_s3_bucket_versioning." + key + "_Versioning"} if "VersioningConfiguration" in p else set()
            self.add(key, "aws_s3_bucket_lifecycle_configuration", {**shared, "rule": rules}, suffix="_Lifecycle", dependencies=dependencies)

    def convert_cognito(self, key, r):
        p, kind = r["Properties"], r["Type"]
        if kind == "AWS::Cognito::UserPool":
            allowed = ["UserPoolName", "AccountRecoverySetting", "AdminCreateUserConfig", "AutoVerifiedAttributes", "DeletionProtection", "EnabledMfas", "MfaConfiguration", "Policies", "UserPoolTags", "UsernameAttributes", "UsernameConfiguration"]
            self.ensure_known(key, p, allowed)
            body = self.copy(p, {"AutoVerifiedAttributes": "auto_verified_attributes", "DeletionProtection": "deletion_protection", "MfaConfiguration": "mfa_configuration", "UsernameAttributes": "username_attributes"})
            body.update(name=tf(self.name(key)), tags=self.tags(p.get("UserPoolTags", {})))
            if p.get("EnabledMfas") != ["SOFTWARE_TOKEN_MFA"]: raise ValueError("Unexpected MFA contract")
            body["software_token_mfa_configuration"] = [{"enabled": True}]
            body["account_recovery_setting"] = [{"recovery_mechanism": [self.copy(x, {"Name": "name", "Priority": "priority"}) for x in p["AccountRecoverySetting"]["RecoveryMechanisms"]]}]
            body["admin_create_user_config"] = [self.copy(p["AdminCreateUserConfig"], {"AllowAdminCreateUserOnly": "allow_admin_create_user_only"})]
            body["username_configuration"] = [self.copy(p["UsernameConfiguration"], {"CaseSensitive": "case_sensitive"})]
            body["password_policy"] = [self.copy(p["Policies"]["PasswordPolicy"], {"MinimumLength": "minimum_length", "RequireLowercase": "require_lowercase", "RequireUppercase": "require_uppercase", "RequireNumbers": "require_numbers", "RequireSymbols": "require_symbols", "TemporaryPasswordValidityDays": "temporary_password_validity_days"})]
            self.add(key, TYPE_MAP[kind], body)
        elif kind == "AWS::Cognito::UserPoolClient":
            mapping = {"UserPoolId": "user_pool_id", "GenerateSecret": "generate_secret", "AllowedOAuthFlowsUserPoolClient": "allowed_oauth_flows_user_pool_client", "AllowedOAuthFlows": "allowed_oauth_flows", "AllowedOAuthScopes": "allowed_oauth_scopes", "SupportedIdentityProviders": "supported_identity_providers", "CallbackURLs": "callback_urls", "LogoutURLs": "logout_urls", "PreventUserExistenceErrors": "prevent_user_existence_errors", "EnableTokenRevocation": "enable_token_revocation", "AccessTokenValidity": "access_token_validity", "IdTokenValidity": "id_token_validity", "RefreshTokenValidity": "refresh_token_validity", "ReadAttributes": "read_attributes", "WriteAttributes": "write_attributes"}
            self.ensure_known(key, p, list(mapping) + ["TokenValidityUnits", "ClientName"])
            body = self.copy(p, mapping); body["name"] = tf(self.name(key))
            # Cognito cannot mutate this flag and the import API omits false.
            # Preserve the public PKCE client on import while creating it false.
            body["lifecycle"] = {"ignore_changes": ["generate_secret"]}
            body["token_validity_units"] = [self.copy(p["TokenValidityUnits"], {"AccessToken": "access_token", "IdToken": "id_token", "RefreshToken": "refresh_token"})]
            self.add(key, TYPE_MAP[kind], body)
        elif kind == "AWS::Cognito::UserPoolDomain":
            self.ensure_known(key, p, ["Domain", "UserPoolId"])
            self.add(key, TYPE_MAP[kind], self.copy(p, {"Domain": "domain", "UserPoolId": "user_pool_id"}))
        else:
            self.ensure_known(key, p, ["GroupName", "UserPoolId"])
            self.add(key, TYPE_MAP[kind], self.copy(p, {"GroupName": "name", "UserPoolId": "user_pool_id"}))

    def convert_api(self, key, r):
        p, kind = r["Properties"], r["Type"]
        if kind == "AWS::ApiGatewayV2::Api":
            self.ensure_known(key, p, ["Name", "ProtocolType"])
            self.add(key, TYPE_MAP[kind], {"name": tf(self.name(key)), "protocol_type": self.value(p["ProtocolType"])})
        elif kind == "AWS::ApiGatewayV2::Integration":
            self.ensure_known(key, p, ["ApiId", "IntegrationType", "IntegrationUri", "PayloadFormatVersion"])
            self.add(key, TYPE_MAP[kind], self.copy(p, {"ApiId": "api_id", "IntegrationType": "integration_type", "IntegrationUri": "integration_uri", "PayloadFormatVersion": "payload_format_version"}), dependencies=self.dep_refs(p))
        elif kind == "AWS::ApiGatewayV2::Route":
            self.ensure_known(key, p, ["ApiId", "RouteKey", "Target"])
            self.add(key, TYPE_MAP[kind], self.copy(p, {"ApiId": "api_id", "RouteKey": "route_key", "Target": "target"}))
        else:
            self.ensure_known(key, p, ["ApiId", "AutoDeploy", "StageName", "DefaultRouteSettings"])
            body = self.copy(p, {"ApiId": "api_id", "AutoDeploy": "auto_deploy", "StageName": "name"})
            body["default_route_settings"] = [self.copy(p["DefaultRouteSettings"], {"ThrottlingBurstLimit": "throttling_burst_limit", "ThrottlingRateLimit": "throttling_rate_limit"})]
            self.add(key, TYPE_MAP[kind], body)

    def convert_statemachine(self, key, r):
        p = r["Properties"]
        self.ensure_known(key, p, ["DefinitionString", "DefinitionSubstitutions", "LoggingConfiguration", "RoleArn", "StateMachineName", "StateMachineType", "Tags"])
        # Substitute each exact ASL placeholder before JSON encoding, so Terraform
        # never treats ASL expressions as its own interpolation syntax.
        definition = json.loads(p["DefinitionString"])
        substitutions = p.get("DefinitionSubstitutions", {})
        def replace(value):
            if isinstance(value, str) and re.fullmatch(r"\$\{[^}]+\}", value):
                token = value[2:-1]
                if token not in substitutions: raise ValueError("Unknown ASL substitution " + token)
                return substitutions[token]
            if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
            if isinstance(value, list): return [replace(v) for v in value]
            return value
        body = self.copy(p, {"RoleArn": "role_arn", "StateMachineType": "type"})
        body.update(name=tf(self.name(key)), definition=self.json(replace(definition)), tags=self.tags(p.get("Tags")))
        logs = p["LoggingConfiguration"]
        body["logging_configuration"] = [{"level": self.value(logs["Level"]), "include_execution_data": self.value(logs["IncludeExecutionData"]), "log_destination": self.value(logs["Destinations"][0]["CloudWatchLogsLogGroup"]["LogGroupArn"])}]
        self.add(key, TYPE_MAP[r["Type"]], body, dependencies=self.dep_refs(p["RoleArn"]) | self.dep_refs(logs))

    def add_implicit_dependencies(self):
        # Names/ARNs are precomputed to avoid function-role-policy and key-policy
        # cycles. Creation-sensitive consumers still await the relevant policies.
        role_policies = {}
        for tf_type, entries in self.resources.items():
            if tf_type != "aws_iam_role_policy": continue
            for label, body in entries.items():
                source = next(k for k in self.cfn if label == k or label.startswith(k + "_Inline"))
                roles = refs(self.cfn[source]["Properties"].get("Roles", []))
                if self.cfn[source]["Type"] == "AWS::IAM::Role": roles.add(source)
                for role in roles: role_policies.setdefault(role, set()).add(tf_type + "." + label)
        for key, source in self.cfn.items():
            if source["Type"] not in ["AWS::Lambda::Function", "AWS::StepFunctions::StateMachine"]: continue
            role_key = "Role" if source["Type"] == "AWS::Lambda::Function" else "RoleArn"
            role_refs = refs(source["Properties"][role_key])
            body = self.resources[TYPE_MAP[source["Type"]]][key]
            deps = set(body.get("depends_on", []))
            for role in role_refs: deps.update(role_policies.get(role, set()))
            if deps: body["depends_on"] = sorted(deps)

    def documents(self):
        required = sorted(set(self.template["Parameters"]) - set(self.defaults))
        variables = {"parameters": {"type": "any", "description": "Reviewed CloudFormation-compatible parameter keys; this module creates native AWS resources.",
                                    "validation": [{"condition": tf("alltrue([for key in " + self.expr(required) + " : contains(keys(var.parameters), key)])"), "error_message": "Missing required platform parameters."}]},
                     "region": {"type": "string"}, "account_id": {"type": "string"}, "stack_name": {"type": "string"},
                     "installation_id": {"type": "string"}, "physical_names": {"type": "map(string)", "default": {}}}
        outputs = {k: {"value": self.value(v["Value"])} for k, v in self.template.get("Outputs", {}).items()}
        if self.module == "foundation": outputs["DashboardApiId"] = {"value": "${aws_apigatewayv2_api.DashboardHttpApi.id}"}
        return {"variables.tf.json": {"variable": variables},
                "main.tf.json": {"terraform": {"required_providers": {"aws": {"source": "hashicorp/aws", "version": "= 6.69.0"}}},
                                 "data": {"aws_partition": {"current": {}}}, "locals": self.locals, "resource": self.resources},
                "outputs.tf.json": {"output": outputs}}

    def import_metadata(self):
        """Describe identifiers without ever storing an installed account's IDs.

        The migration driver resolves these templates from its private snapshot.
        A CloudFormation resource's physical ID is not always a Terraform ID.
        """
        primary_ids = {
            "aws_apigatewayv2_api": "{cfn_physical_id}",
            "aws_apigatewayv2_integration": "{api_id}/{cfn_physical_id}",
            "aws_apigatewayv2_route": "{api_id}/{cfn_physical_id}",
            "aws_apigatewayv2_stage": "{api_id}/{stage_name}",
            "aws_cloudwatch_metric_alarm": "{alarm_name}",
            "aws_cognito_user_pool": "{cfn_physical_id}",
            "aws_cognito_user_pool_client": "{user_pool_id}/{cfn_physical_id}",
            "aws_cognito_user_pool_domain": "{domain}",
            "aws_cognito_user_group": "{user_pool_id}/{group_name}",
            "aws_dynamodb_table": "{table_name}",
            "aws_cloudwatch_event_bus": "{event_bus_name}",
            "aws_cloudwatch_event_rule": "{rule_name} for default bus; {event_bus_name}/{rule_name} for custom bus",
            "aws_cloudwatch_event_target": "{rule_name}/{target_id} for default bus; {event_bus_name}/{rule_name}/{target_id} for custom bus",
            "aws_iam_role": "{role_name}",
            "aws_iam_role_policy": "{role_name}:{policy_name}",
            "aws_kms_key": "{key_id}",
            "aws_lambda_function": "{function_name}",
            "aws_lambda_alias": "{function_name}/{alias_name}",
            "aws_lambda_permission": "{function_name_or_name_with_qualifier}/{statement_id}",
            "aws_lambda_function_event_invoke_config": "{function_name}:{qualifier}",
            "aws_lambda_event_source_mapping": "{mapping_uuid}",
            "aws_cloudwatch_log_group": "{log_group_name}",
            "aws_cloudwatch_log_metric_filter": "{log_group_name}:{filter_name}",
            "aws_s3_bucket": "{bucket_name}",
            "aws_s3_bucket_policy": "{bucket_name}",
            "aws_s3_bucket_versioning": "{bucket_name}",
            "aws_s3_bucket_ownership_controls": "{bucket_name}",
            "aws_s3_bucket_public_access_block": "{bucket_name}",
            "aws_s3_bucket_server_side_encryption_configuration": "{bucket_name}",
            "aws_s3_bucket_lifecycle_configuration": "{bucket_name}",
            "aws_sns_topic": "{topic_arn}",
            "aws_sns_topic_policy": "{topic_arn}",
            "aws_sns_topic_subscription": "{subscription_arn}",
            "aws_sqs_queue": "{queue_url}",
            "aws_sqs_queue_policy": "{queue_url}",
            "aws_sfn_state_machine": "{state_machine_arn}",
        }
        for logical, mapping in self.mapping.items():
            source = self.cfn[logical]
            mapping["source_properties"] = source.get("Properties", {})
            mapping["counted"] = bool(source.get("Condition"))
            mapping["terraform_imports"] = []
            for address in mapping["resources"]:
                tf_type, label = address.split(".", 1)
                body = self.resources[tf_type][label]
                count_suffix = "[0]" if mapping["counted"] else ""
                entry = {"address": address + count_suffix, "type": tf_type,
                         "id_template": primary_ids[tf_type],
                         "configured_identifiers": {k: v for k, v in body.items() if k in
                             {"name", "function_name", "qualifier", "statement_id", "role", "policy", "rule", "event_bus_name",
                              "target_id", "bucket", "arn", "queue_url", "user_pool_id", "domain", "api_id", "log_group_name"}}}
                # Policy bodies are reviewed source, not import identifiers.
                entry["configured_identifiers"].pop("policy", None)
                mapping["terraform_imports"].append(entry)
        return self.mapping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True, help="terraform providers schema -json from hashicorp/aws 6.69.0")
    parser.add_argument("--check", action="store_true", help="Fail if committed generated modules differ; do not write")
    args = parser.parse_args()
    schema = json.loads(args.schema.read_text(encoding="utf-8-sig"))["provider_schemas"]["registry.terraform.io/hashicorp/aws"]["resource_schemas"]
    manifest = {"schema_version": "1.0", "provider": "hashicorp/aws", "provider_version": "6.69.0", "modules": {},
                "ownership": "Terraform owns the platform; runtime discovery/response owns service ACL rules, associations, IPSet addresses and registry records. Never import these mutable service objects into this platform state.",
                "immutable_lambda_versions": "Existing published versions are retained outside individual Terraform resource ownership. Functions publish=true; live aliases use the reviewed function.version. No existing immutable version imports/deletes."}
    changed = []
    for name, filename in MODULES.items():
        template = json.loads((ROOT / "infrastructure" / filename).read_text(encoding="utf-8"))
        converter = Converter(name, template, schema)
        docs = converter.convert()
        for filename, document in docs.items():
            path = ROOT / "terraform/modules" / name / filename
            encoded = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
            if not path.exists() or path.read_text(encoding="utf-8") != encoded:
                changed.append(path.relative_to(ROOT).as_posix())
                if not args.check:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(encoded, encoding="utf-8")
        manifest["modules"][name] = converter.import_metadata()
    path = ROOT / "terraform/resource-map.json"
    encoded = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    if not path.exists() or path.read_text(encoding="utf-8") != encoded:
        changed.append(path.relative_to(ROOT).as_posix())
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(encoded, encoding="utf-8")
    if args.check and changed: raise SystemExit("Generated Terraform files differ: " + ", ".join(changed))
    print(json.dumps({"status": "MATCHED" if args.check else "GENERATED", "modules": len(MODULES), "changed_files": changed}))


if __name__ == "__main__": main()
