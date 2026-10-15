"""Discover unknown existing HTTP services and preserve their existing WAF rules."""
import copy
import base64
import hashlib
import json
import os
import re
import time
import uuid

from .blocker import acquire, release
from .service_scope import SERVICE, revision_for


def service_identity(resource):
    requested = resource.get("tags", {}).get("security:service-id")
    if requested:
        if not SERVICE.fullmatch(requested):
            raise ValueError("INVALID_SERVICE_TAG")
        return requested
    return "web-" + hashlib.sha256(resource["arn"].encode()).hexdigest()[:24]


def selected(resource, scope):
    if resource.get("type") not in {"ALB", "CLOUDFRONT"} or resource.get("public") is not True:
        return False
    if scope not in {"tagged", "all-supported"}:
        raise ValueError("INVALID_DISCOVERY_SCOPE")
    tags = resource.get("tags", {})
    if tags.get("security:managed") == "false" or tags.get("security:control-plane") == "true":
        return False
    return scope == "all-supported" or tags.get("security:managed") == "true"


def managed_rules(service_id, ipv4_arn, ipv6_arn):
    stem = "security-" + service_id
    def rule(name, statement, action=None, override=None):
        value = {"Name": name, "Statement": statement, "VisibilityConfig": {
            "SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": True, "MetricName": name}}
        value.update({"Action": action} if action is not None else {"OverrideAction": override})
        return value
    # The static baseline is observation-first; only case-authorized IPSet
    # entries actually block. Managed-rule COUNT avoids breaking unknown apps.
    return [rule(stem + "-blocked-ipv4", {"IPSetReferenceStatement": {"ARN": ipv4_arn}}, {"Block": {}}),
            rule(stem + "-blocked-ipv6", {"IPSetReferenceStatement": {"ARN": ipv6_arn}}, {"Block": {}}),
            rule(stem + "-common", {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}}, override={"Count": {}}),
            rule(stem + "-bad-inputs", {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesKnownBadInputsRuleSet"}}, override={"Count": {}})]


def data_protection():
    # New ACLs protect stored request data, including match details. Redaction
    # alone is tied to rule FieldToMatch and cannot cover Headers statements.
    fields = [{"FieldType": "SINGLE_HEADER", "FieldKeys": ["authorization", "cookie", "x-api-key"]},
              {"FieldType": "QUERY_STRING"}, {"FieldType": "BODY"}]
    return {"DataProtections": [{"Field": field, "Action": "SUBSTITUTION", "ExcludeRuleMatchDetails": False,
                                 "ExcludeRateBasedDetails": False} for field in fields]}


def merge_rules(current, desired):
    merged = copy.deepcopy(current)
    names = {item["Name"]: item for item in current}
    priorities = {item["Priority"] for item in current}
    cursor = max(priorities, default=-1) + 1
    for item in desired:
        if item["Name"] in names:
            # An administrator's change is never silently reversed.
            existing = dict(names[item["Name"]]); existing.pop("Priority", None)
            if existing != item:
                raise ValueError("MANAGED_RULE_CHANGED_REVIEW_REQUIRED")
            continue
        if cursor > 2147483647:
            raise ValueError("WAF_PRIORITY_EXHAUSTED")
        merged.append(dict(item, Priority=cursor)); priorities.add(cursor); cursor += 1
    return merged


def reconcile(resource, api, *, registry, leases, scope, account, audit_bucket,
              response_mode="observe", allowed_actions=None, retention=90):
    if response_mode not in {"observe", "enforce"}:
        raise ValueError("INVALID_RESPONSE_POLICY")
    if allowed_actions is not None and (not allowed_actions or set(allowed_actions) - {"monitor", "block_ip"}):
        raise ValueError("INVALID_ACTION_POLICY")
    if not selected(resource, scope):
        return {"resource_arn": resource["arn"], "status": "OUT_OF_INSTALLATION_SCOPE"}
    if resource["arn"].split(":")[4] != account:
        raise ValueError("DISCOVERY_ACCOUNT_MISMATCH")
    service_id = service_identity(resource)
    waf_region = "us-east-1" if resource["type"] == "CLOUDFRONT" else resource["region"]
    # Region-specific log transport must exist before the first WAF mutation.
    api.validate_ingress(waf_region, account)
    owner, lock_key = uuid.uuid4().hex, "onboard#" + service_id
    if not acquire(leases, lock_key, owner, ttl=600):
        return {"service_id": service_id, "status": "RECONCILE_IN_PROGRESS"}
    try:
        previous = registry.get_item(Key={"service_id": service_id}, ConsistentRead=True).get("Item")
        if previous and previous.get("resource_arns") != [resource["arn"]]:
            raise ValueError("SERVICE_ID_COLLISION")
        waf_scope = "CLOUDFRONT" if resource["type"] == "CLOUDFRONT" else "REGIONAL"
        acl = api.current_acl(resource)
        if acl:
            item = acl["WebACL"]
            if item.get("ManagedByFirewallManager") or item.get("RetrofittedByFirewallManager"):
                raise ValueError("FIREWALL_MANAGER_OWNERSHIP_REVIEW_REQUIRED")
            # A service's response IPSet must never become a global block list
            # for every resource sharing this ACL. Verify all associations.
            if api.acl_resources(resource, item["ARN"]) != {resource["arn"]}:
                raise ValueError("SHARED_WEBACL_REVIEW_REQUIRED")
            api.logging_plan(waf_region, item["ARN"], service_id)
        # Only name-stable platform IPsets are created/reused. Their addresses
        # and an existing web ACL's unrelated rules remain untouched.
        ipv4 = api.ensure_ipset(waf_region, waf_scope, "security-" + service_id + "-ipv4", "IPV4")
        ipv6 = api.ensure_ipset(waf_region, waf_scope, "security-" + service_id + "-ipv6", "IPV6")
        desired = managed_rules(service_id, ipv4["ARN"], ipv6["ARN"])
        if acl:
            rules = merge_rules(acl["WebACL"].get("Rules", []), desired)
            api.audit_snapshot(audit_bucket, service_id, resource, acl)
            acl_arn = (api.update_acl(waf_region, waf_scope, acl, rules)
                       if rules != acl["WebACL"].get("Rules", []) else acl["WebACL"]["ARN"])
        else:
            acl_arn = api.ensure_acl(waf_region, waf_scope, "security-" + service_id,
                                     [dict(item, Priority=index) for index, item in enumerate(desired)])
            if api.acl_resources(resource, acl_arn):
                raise ValueError("RECOVERED_WEBACL_ALREADY_ASSOCIATED")
            api.audit_snapshot(audit_bucket, service_id, resource, {"previous_web_acl_arn": None})
            api.attach(resource, acl_arn)
        # Association and logging are verified before registry.enabled is true.
        if api.associated_acl(resource) != acl_arn:
            raise ValueError("WAF_ASSOCIATION_NOT_VERIFIED")
        if api.acl_resources(resource, acl_arn) != {resource["arn"]}:
            raise ValueError("WAF_EXCLUSIVE_ASSOCIATION_NOT_VERIFIED")
        logging_state = api.ensure_logging(waf_region, acl_arn, service_id, retention)
        verified_log = api.logging_plan(waf_region, acl_arn, service_id)
        record = {"service_id": service_id, "environment": os.environ.get("ENVIRONMENT", "production"),
                  "account_id": account, "region": resource["region"], "enabled": True,
                  "response_mode": response_mode, "resource_arns": [resource["arn"]],
                  "resource_type": resource["type"], "web_acl_arn": acl_arn, "waf_ipset_arn": ipv4["ARN"],
                  "waf_ipv6_ipset_arn": ipv6["ARN"], "waf_scope": waf_scope,
                  "allowed_actions": allowed_actions or ["monitor", "block_ip"], "isolation_target_ids": [],
                  "nacl_enabled": False, "audit_bucket": audit_bucket,
                  "logging_state": logging_state, "protected_cidrs": [], "updated_at": int(time.time())}
        record.update(log_group_name=verified_log["name"], log_region=waf_region)
        if previous:
            # Preserve the operator's explicit policy on periodic reconciliation.
            for key in ("response_mode", "allowed_actions", "protected_cidrs", "allowed_admin_groups", "allowed_reader_groups",
                        "report_bucket", "rate_limit", "auto_block_policy", "manual_block_enabled", "isolation_target_ids", "nacl_enabled",
                        "nacl_id", "nacl_slots", "vpc_id", "nacl_placeholder_cidr"):
                if key in previous:
                    record[key] = previous[key]
            # Installation-level action removal is a ceiling, even when a
            # previous per-service policy is preserved during reconciliation.
            if allowed_actions is not None:
                record["allowed_actions"] = [action for action in record["allowed_actions"] if action in allowed_actions]
            record["revision"] = revision_for(record)
            registry.put_item(Item=record, ConditionExpression="revision = :previous",
                              ExpressionAttributeValues={":previous": previous["revision"]})
        else:
            record["revision"] = revision_for(record)
            registry.put_item(Item=record, ConditionExpression="attribute_not_exists(service_id)")
        return {"service_id": service_id, "resource_arn": resource["arn"], "status": "PROTECTED",
                "web_acl_arn": acl_arn, "logging_state": logging_state, "response_mode": record["response_mode"]}
    finally:
        release(leases, lock_key, owner)


class AWS:
    def __init__(self, ingress_arns=None):
        import boto3
        from botocore.config import Config
        self.boto3 = boto3
        self.config = Config(connect_timeout=2, read_timeout=10, retries={"mode": "standard", "total_max_attempts": 3})
        self.ingress = ingress_arns or {}

    def client(self, service, region):
        return self.boto3.client(service, region_name=region, config=self.config)

    def validate_ingress(self, region, account):
        value = self.ingress.get(region, "")
        if not re.fullmatch(r"arn:aws(?:-us-gov|-cn)?:lambda:" + re.escape(region) + ":" + re.escape(account) + r":function:[A-Za-z0-9_-]+", value):
            raise ValueError("REGIONAL_LOG_INGRESS_NOT_DEPLOYED")

    def resources(self, regions):
        for region in regions:
            elb = self.client("elbv2", region)
            for page in elb.get_paginator("describe_load_balancers").paginate():
                for value in page.get("LoadBalancers", []):
                    if value.get("Type") != "application":
                        continue
                    arn = value["LoadBalancerArn"]
                    tags = elb.describe_tags(ResourceArns=[arn])["TagDescriptions"][0].get("Tags", [])
                    yield {"arn": arn, "type": "ALB", "region": region,
                           "public": value.get("Scheme") == "internet-facing",
                           "tags": {item["Key"]: item["Value"] for item in tags}}
        cf = self.client("cloudfront", "us-east-1")
        for page in cf.get_paginator("list_distributions").paginate():
            for value in page.get("DistributionList", {}).get("Items", []):
                tags = cf.list_tags_for_resource(Resource=value["ARN"]).get("Tags", {}).get("Items", [])
                yield {"arn": value["ARN"], "type": "CLOUDFRONT", "region": "us-east-1", "id": value["Id"],
                       "public": value.get("Enabled") is True and value.get("ConnectionMode", "direct") == "direct",
                       "tags": {item["Key"]: item["Value"] for item in tags}}

    def ensure_ipset(self, region, scope, name, family):
        waf = self.client("wafv2", region)
        marker = None
        while True:
            args = {"Scope": scope, "Limit": 100}
            if marker: args["NextMarker"] = marker
            response = waf.list_ip_sets(**args)
            for item in response.get("IPSets", []):
                if item["Name"] == name:
                    result = waf.get_ip_set(Name=name, Id=item["Id"], Scope=scope)["IPSet"]
                    if result["IPAddressVersion"] != family:
                        raise ValueError("MANAGED_IPSET_FAMILY_CONFLICT")
                    return result
            marker = response.get("NextMarker")
            if not marker: break
        return waf.create_ip_set(Name=name, Scope=scope, IPAddressVersion=family, Addresses=[],
                                 Tags=[{"Key": "security:platform", "Value": "enterprise"}])["Summary"]

    def associated_acl(self, resource):
        if resource["type"] == "CLOUDFRONT":
            config = self.client("cloudfront", "us-east-1").get_distribution_config(Id=resource["id"])["DistributionConfig"]
            if config.get("ConnectionMode", "direct") != "direct":
                raise ValueError("DISTRIBUTION_TENANCY_REVIEW_REQUIRED")
            return config.get("WebACLId") or None
        waf = self.client("wafv2", resource["region"])
        try:
            return waf.get_web_acl_for_resource(ResourceArn=resource["arn"]).get("WebACL", {}).get("ARN")
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") == "WAFNonexistentItemException": return None
            raise

    def current_acl(self, resource):
        arn = self.associated_acl(resource)
        if not arn: return None
        if ":wafv2:" not in arn:
            raise ValueError("WAF_CLASSIC_MIGRATION_REQUIRED")
        parts = arn.split(":", 5); path = parts[5].split("/")
        scope = "CLOUDFRONT" if path[0] == "global" else "REGIONAL"
        return self.client("wafv2", parts[3]).get_web_acl(Name=path[-2], Id=path[-1], Scope=scope)

    def acl_resources(self, resource, acl_arn):
        if resource["type"] == "CLOUDFRONT":
            result, marker = set(), None
            cf = self.client("cloudfront", "us-east-1")
            while True:
                args = {"WebACLId": acl_arn, "MaxItems": "100"}
                if marker: args["Marker"] = marker
                page = cf.list_distributions_by_web_acl_id(**args)["DistributionList"]
                result.update(item["ARN"] for item in page.get("Items", []))
                marker = page.get("NextMarker")
                if not page.get("IsTruncated") or not marker: break
            marker = None
            while True:
                args = {"WebACLArn": acl_arn, "MaxItems": 100}
                if marker: args["Marker"] = marker
                page = cf.list_distribution_tenants_by_customization(**args)
                result.update(item["Arn"] for item in page.get("DistributionTenantList", []))
                marker = page.get("NextMarker")
                if not marker: break
            return result
        waf = self.client("wafv2", resource["region"])
        types = waf.meta.service_model.operation_model("ListResourcesForWebACL").input_shape.members["ResourceType"].enum
        result = set()
        # Query every SDK-supported regional resource type. Access-denied or
        # incomplete inventory fails closed instead of assuming exclusive use.
        for kind in types:
            result.update(waf.list_resources_for_web_acl(WebACLArn=acl_arn, ResourceType=kind).get("ResourceArns", []))
        return result

    def logging_plan(self, region, acl_arn, service_id):
        waf = self.client("wafv2", region)
        try:
            configuration = waf.get_logging_configuration(ResourceArn=acl_arn)["LoggingConfiguration"]
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") != "WAFNonexistentItemException": raise
            configuration = None
        if configuration:
            if configuration.get("LogScope", "CUSTOMER") != "CUSTOMER" or configuration.get("ManagedByFirewallManager"):
                raise ValueError("LOGGING_OWNERSHIP_REVIEW_REQUIRED")
            destinations = configuration.get("LogDestinationConfigs", [])
            match = (re.fullmatch(r"arn:(aws(?:-us-gov|-cn)?):logs:" + re.escape(region) + ":" +
                     re.escape(acl_arn.split(":")[4]) + r":log-group:(aws-waf-logs-[^:*]+)(?::\*)?", destinations[0])
                     if len(destinations) == 1 else None)
            if not match:
                raise ValueError("EXISTING_LOG_SINK_ADAPTER_REQUIRED")
            # A pre-existing filter dropping COUNT could hide managed baseline
            # observations. Keep it intact and require a conscious review.
            if configuration.get("LoggingFilter"):
                raise ValueError("EXISTING_LOG_FILTER_REVIEW_REQUIRED")
            name = match.group(2)
        else:
            name = "aws-waf-logs-security-" + service_id
        filters = self.client("logs", region).describe_subscription_filters(logGroupName=name).get("subscriptionFilters", []) if configuration else []
        owned = [item for item in filters if item.get("filterName") == "security-service-ingress"]
        if owned and (owned[0].get("destinationArn") != self.ingress.get(region) or owned[0].get("filterPattern") != ""):
            raise ValueError("LOG_SUBSCRIPTION_CHANGED_REVIEW_REQUIRED")
        if not owned and len(filters) >= 2:
            raise ValueError("LOG_SUBSCRIPTION_SLOTS_EXHAUSTED")
        return {"name": name, "existing": bool(configuration), "subscription_exists": bool(owned)}

    def preview(self, resource, service_id):
        acl = self.current_acl(resource)
        if not acl: return {"web_acl_arn": None, "rule_count": 0, "logging_adapter": "NEW_CLOUDWATCH", "status": "CANDIDATE"}
        item = acl["WebACL"]
        projection = {"web_acl_arn": item["ARN"], "rule_count": len(item.get("Rules", [])),
                      "existing_rule_names": [rule["Name"] for rule in item.get("Rules", [])], "status": "CANDIDATE"}
        if item.get("ManagedByFirewallManager") or item.get("RetrofittedByFirewallManager"):
            return dict(projection, status="REVIEW_REQUIRED", reason="FIREWALL_MANAGER_OWNERSHIP_REVIEW_REQUIRED")
        if self.acl_resources(resource, item["ARN"]) != {resource["arn"]}:
            return dict(projection, status="REVIEW_REQUIRED", reason="SHARED_WEBACL_REVIEW_REQUIRED")
        plan = self.logging_plan(item["ARN"].split(":")[3], item["ARN"], service_id)
        return dict(projection, logging_adapter="EXISTING_CLOUDWATCH" if plan["existing"] else "NEW_CLOUDWATCH")

    def update_acl(self, region, scope, snapshot, rules):
        waf = self.client("wafv2", region)
        item = snapshot["WebACL"]
        # SDK schema prevents read-only fields, while retaining all currently
        # supported mutable settings including future API additions.
        allowed = set(waf.meta.service_model.operation_model("UpdateWebACL").input_shape.members)
        args = {key: value for key, value in item.items() if key in allowed}
        args.update(Scope=scope, LockToken=snapshot["LockToken"], Rules=rules)
        waf.check_capacity(Scope=scope, Rules=rules)
        waf.update_web_acl(**args)  # stale LockToken fails; never overwrite/retry a different snapshot
        return item["ARN"]

    def ensure_acl(self, region, scope, name, rules):
        waf = self.client("wafv2", region)
        marker = None
        while True:
            args = {"Scope": scope, "Limit": 100}
            if marker: args["NextMarker"] = marker
            response = waf.list_web_acls(**args)
            for item in response.get("WebACLs", []):
                if item["Name"] == name:
                    current = waf.get_web_acl(Name=name, Id=item["Id"], Scope=scope)
                    # A recoverable prior creation is accepted only if exact rules match.
                    if (current["WebACL"].get("Rules") != rules or current["WebACL"].get("DefaultAction") != {"Allow": {}}
                            or current["WebACL"].get("DataProtectionConfig") != data_protection()):
                        raise ValueError("MANAGED_WEBACL_CONFLICT")
                    return item["ARN"]
            marker = response.get("NextMarker")
            if not marker: break
        waf.check_capacity(Scope=scope, Rules=rules)
        return waf.create_web_acl(Name=name, Scope=scope, DefaultAction={"Allow": {}}, Rules=rules,
                                  DataProtectionConfig=data_protection(),
                                  VisibilityConfig={"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": True, "MetricName": name},
                                  Tags=[{"Key": "security:platform", "Value": "enterprise"}])["Summary"]["ARN"]

    def attach(self, resource, acl_arn):
        if resource["type"] == "ALB":
            waf = self.client("wafv2", resource["region"])
            if self.associated_acl(resource): raise ValueError("CONCURRENT_WAF_ASSOCIATION_CHANGE")
            waf.associate_web_acl(WebACLArn=acl_arn, ResourceArn=resource["arn"])
        else:
            cf = self.client("cloudfront", "us-east-1")
            snapshot = cf.get_distribution_config(Id=resource["id"])
            config = snapshot["DistributionConfig"]
            if config.get("WebACLId"): raise ValueError("CONCURRENT_WAF_ASSOCIATION_CHANGE")
            config["WebACLId"] = acl_arn
            cf.update_distribution(Id=resource["id"], IfMatch=snapshot["ETag"], DistributionConfig=config)

    def audit_snapshot(self, bucket, service_id, resource, snapshot):
        s3 = self.client("s3", os.environ.get("CONTROL_PLANE_REGION", os.environ.get("AWS_REGION")))
        key = f"operations/onboarding/{service_id}/{time.time_ns()}-{uuid.uuid4().hex}.json"
        def encode(value):
            if isinstance(value, bytes): return {"__bytes_base64__": base64.b64encode(value).decode()}
            raise TypeError("UNSUPPORTED_SNAPSHOT_TYPE")
        s3.put_object(Bucket=bucket, Key=key, Body=json.dumps({"schema_version": "1.0", "resource_arn": resource["arn"], "snapshot": snapshot}, default=encode).encode(),
                      ContentType="application/json", IfNoneMatch="*")

    def ensure_logging(self, region, acl_arn, service_id, retention):
        waf = self.client("wafv2", region)
        logs = self.client("logs", region)
        destination = self.ingress.get(region)
        if not destination:
            raise ValueError("REGIONAL_LOG_INGRESS_NOT_DEPLOYED")
        plan = self.logging_plan(region, acl_arn, service_id)
        name = plan["name"]
        if not plan["existing"]:
            try:
                logs.create_log_group(logGroupName=name, tags={"security:platform": "enterprise", "security:service-id": service_id})
            except Exception as error:
                if getattr(error, "response", {}).get("Error", {}).get("Code") != "ResourceAlreadyExistsException": raise
            logs.put_retention_policy(logGroupName=name, retentionInDays=retention)
            account = acl_arn.split(":")[4]
            arn = f"arn:{acl_arn.split(':')[1]}:logs:{region}:{account}:log-group:{name}"
            waf.put_logging_configuration(LoggingConfiguration={"ResourceArn": acl_arn, "LogDestinationConfigs": [arn],
                "RedactedFields": [{"SingleHeader": {"Name": key}} for key in ("authorization", "cookie", "x-api-key")] + [{"QueryString": {}}]})
        if not plan["subscription_exists"]:
            logs.put_subscription_filter(logGroupName=name, filterName="security-service-ingress", filterPattern="",
                                         destinationArn=destination)
        return "INTEGRATED"


def handler(event, context):
    import boto3
    account = os.environ["EXPECTED_ACCOUNT"]
    region_value = os.environ["DISCOVERY_REGIONS"]
    regions = json.loads(region_value) if region_value.startswith("[") else region_value.split(",")
    if not regions or any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", value) for value in regions):
        raise ValueError("INVALID_DISCOVERY_REGIONS")
    operation = event.get("operation", "reconcile") if isinstance(event, dict) else "reconcile"
    if operation not in {"discover", "reconcile"}: raise ValueError("INVALID_DISCOVERY_OPERATION")
    if isinstance(event, dict) and event.get("account") not in (None, account): raise ValueError("UNTRUSTED_DISCOVERY_EVENT")
    api = AWS(json.loads(os.environ.get("INGRESS_ARNS_JSON", "{}")))
    resource = boto3.resource("dynamodb", region_name=os.environ.get("CONTROL_PLANE_REGION", os.environ["AWS_REGION"]))
    registry, leases = resource.Table(os.environ["REGISTRY_TABLE"]), resource.Table(os.environ["LEASE_TABLE"])
    results = []
    for candidate in api.resources(regions):
        exclusions = json.loads(os.environ.get("EXCLUDE_TAGS_JSON", '{"security:exclude":"true"}'))
        if any(candidate.get("tags", {}).get(key) == value for key, value in exclusions.items()):
            continue
        if not selected(candidate, os.environ["INSTALLATION_SCOPE"]): continue
        if len(results) >= 500: raise ValueError("DISCOVERY_LIMIT_REQUIRES_PARTITIONED_INSTALLATION")
        if operation == "discover":
            try:
                details = api.preview(candidate, service_identity(candidate))
            except Exception as error:
                reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z0-9_]+", str(error)) else "DISCOVERY_INVENTORY_REVIEW_REQUIRED"
                details = {"status": "REVIEW_REQUIRED", "reason": reason}
            results.append({"resource_arn": candidate["arn"], "resource_type": candidate["type"],
                            "region": candidate["region"], "service_id": service_identity(candidate), **details})
            continue
        try:
            results.append(reconcile(candidate, api, registry=registry, leases=leases, scope=os.environ["INSTALLATION_SCOPE"],
                account=account, audit_bucket=os.environ["AUDIT_BUCKET"], response_mode=os.environ.get("RESPONSE_MODE", "observe"),
                allowed_actions=os.environ.get("ALLOWED_ACTIONS", "monitor,block_ip").split(","),
                retention=int(os.environ.get("LOG_RETENTION_DAYS", "90"))))
        except Exception as error:
            reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z0-9_]+", str(error)) else "ONBOARDING_FAILED_REVIEW_REQUIRED"
            results.append({"resource_arn": candidate["arn"], "status": "REVIEW_REQUIRED", "reason": reason})
    # No original distribution configs, origin credentials, logs or errors here.
    print(json.dumps({"operation": operation, "count": len(results), "installation_id": os.environ.get("INSTALLATION_ID", "unconfigured"),
                      "environment": os.environ.get("ENVIRONMENT", "unconfigured"),
                      "review_required": sum(x["status"] == "REVIEW_REQUIRED" for x in results)}))
    return {"operation": operation, "resources": results}
