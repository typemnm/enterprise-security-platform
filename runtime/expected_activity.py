"""Prove an expected control-plane call by its AWS-issued request ID.

The receipt writer's IAM permission must require lambda:SourceFunctionArn.
Names, role prefixes, public source IPs and user agents are never proof.
Raw CloudTrail collection is never suppressed by this module.
"""
import hashlib
import os
import re
import time

FUNCTION = re.compile(r"arn:(aws(?:-us-gov|-cn)?):lambda:([a-z0-9-]+):(\d{12}):function:([A-Za-z0-9_-]{1,64})\Z")
REQUEST = re.compile(r"[A-Za-z0-9-]{8,128}\Z")


def identity(account, region, request_id):
    if not re.fullmatch(r"\d{12}", str(account)) or not REQUEST.fullmatch(str(request_id)):
        raise ValueError("INVALID_ACTIVITY_IDENTITY")
    return hashlib.sha256(f"{account}:{region}:{request_id}".encode()).hexdigest()


def record(table, *, account, region, request_id, function_arn, execution_id, resource_arn,
           api="GetSecretValue", observed_at=None):
    match = FUNCTION.fullmatch(str(function_arn))
    if (not match or match.group(2, 3) != (region, account) or api != "GetSecretValue"
            or not str(resource_arn).startswith(f"arn:{match.group(1)}:secretsmanager:{region}:{account}:secret:")
            or not REQUEST.fullmatch(str(execution_id))):
        raise ValueError("INVALID_EXPECTED_ACTIVITY")
    now = int(time.time() if observed_at is None else observed_at)
    item = {"activity_id": identity(account, region, request_id), "request_id": request_id,
            "account_id": account, "region": region, "api": api, "resource_arn": resource_arn,
            "function_arn": function_arn, "execution_id": execution_id, "observed_at": now,
            "expires_at": now + 86400, "classification": "EXPECTED_CONTROL_PLANE_ACTIVITY"}
    table.put_item(Item=item, ConditionExpression="attribute_not_exists(activity_id)")
    return item["activity_id"]


def expected(event, table, *, account, region, allowed_functions, allowed_resources, now=None):
    if not isinstance(event, dict) or (event.get("account"), event.get("region"), event.get("source"), event.get("detail-type")) != (
            account, region, "aws.secretsmanager", "AWS API Call via CloudTrail"):
        return False
    detail = event.get("detail", {})
    if (not isinstance(detail, dict) or detail.get("eventName") != "GetSecretValue"
            or detail.get("eventSource") != "secretsmanager.amazonaws.com"
            or detail.get("recipientAccountId") != account or detail.get("awsRegion") != region
            or detail.get("errorCode") is not None or detail.get("errorMessage") is not None):
        return False
    try:
        request_id = detail["requestID"]
        receipt = table.get_item(Key={"activity_id": identity(account, region, request_id)},
                                 ConsistentRead=True).get("Item", {})
        current = int(time.time() if now is None else now)
        function_arn, resource = receipt.get("function_arn"), receipt.get("resource_arn")
        requested = detail.get("requestParameters", {}).get("secretId")
        if (function_arn not in allowed_functions or resource not in allowed_resources
                or requested not in {resource, resource.split(":secret:", 1)[-1].rsplit("-", 1)[0]}
                or receipt.get("request_id") != request_id or receipt.get("account_id") != account
                or receipt.get("region") != region or receipt.get("api") != "GetSecretValue"
                or receipt.get("classification") != "EXPECTED_CONTROL_PLANE_ACTIVITY"
                or int(receipt.get("expires_at", 0)) <= current
                or not current - 86400 <= int(receipt.get("observed_at", 0)) <= current + 30):
            return False
        principal = detail.get("userIdentity", {})
        origin = principal.get("inScopeOf")
        if origin is not None and (origin.get("issuerType") != "AWS::Lambda::Function"
                or origin.get("credentialsIssuedTo") != function_arn
                or origin.get("sourceAccount", account) != account
                or origin.get("sourceArn", function_arn) != function_arn):
            return False
        if principal.get("type") != "AssumedRole" or principal.get("accountId") != account:
            return False
        # Matching principal plus a source-function-conditioned request receipt
        # is required even on older CloudTrail records without inScopeOf.
        if not str(principal.get("arn", "")).endswith("/" + function_arn.rsplit(":", 1)[-1]):
            return False
        resources = detail.get("resources")
        if resources is not None and (not isinstance(resources, list) or len(resources) != 1
                or resources[0].get("ARN") != resource):
            return False
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    except Exception:
        # A missing/unavailable proof is never a reason to suppress an alert.
        return False


class AttestedSecrets:
    """SDK proxy: persist metadata only; credential values never enter the table."""
    def __init__(self, client, table, context, account, region, on_failure=None):
        self.client, self.table, self.context = client, table, context
        self.account, self.region, self.on_failure = account, region, on_failure

    def get_secret_value(self, **kwargs):
        result = self.client.get_secret_value(**kwargs)
        function_arn = self.context.invoked_function_arn
        parts = function_arn.split(":")
        function_arn = ":".join(parts[:7])
        try:
            record(self.table, account=self.account, region=self.region,
                   request_id=result.get("ResponseMetadata", {}).get("RequestId"),
                   function_arn=function_arn, execution_id=self.context.aws_request_id,
                   resource_arn=result.get("ARN") or kwargs["SecretId"])
        except Exception:
            # Delivery remains available; the unproved call is investigated.
            if self.on_failure:
                self.on_failure("EXPECTED_ACTIVITY_RECEIPT_FAILED")
        return result


def wrap(client, context):
    table_name = os.environ.get("EXPECTED_ACTIVITY_TABLE")
    if not table_name:
        return client
    import boto3
    return AttestedSecrets(client, boto3.resource("dynamodb").Table(table_name), context,
                           os.environ["EXPECTED_ACCOUNT"], os.environ.get("AWS_REGION", ""))
