"""Fail closed and publish a bounded failure report without raw SFN Cause."""
from datetime import datetime, timezone
import os
import re
import time
from outcome_metadata import CASE, error_fields, safe_code, validate_service
from publication import CasePublicationStore, PublicationCoordinator, make_job
from publication_events import make_outbox

STAGES = {"AI1": "AI1_FAILED", "AI2": "AI2_FAILED", "APPROVAL": "APPROVAL_FAILED", "PUBLICATION": "PUBLICATION_FAILED"}
FINISHED = {"AUTO_BLOCKED", "AUTO_BLOCK_PARTIAL", "AUTO_BLOCK_FAILED", "AUTO_BLOCK_UNVERIFIED", "AUTO_ISOLATED",
            "AUTO_ISOLATION_FAILED", "AUTO_MONITORED", "AUTO_DRY_RUN", "ISOLATED", "ISOLATION_FAILED", "REJECTED", "TIMED_OUT",
            "IP_BLOCKED", "BLOCK_PARTIAL", "BLOCK_FAILED", "BLOCK_UNVERIFIED", "NO_ACTION", "AUTO_RESPONSE_EXEMPT"}


def identify(event):
    case_id = event.get("case_id")
    report = event.get("report")
    if not case_id and isinstance(report, dict):
        match = re.fullmatch(r"investigations/(inv-[0-9a-f]{32})/report\.json", str(report.get("key", "")))
        case_id = match.group(1) if match else None
    if not isinstance(case_id, str) or not CASE.fullmatch(case_id):
        raise ValueError("TERMINAL_CASE_ID_REQUIRED")
    return case_id


def normalize_eventbridge(event, *, machines, account, region, sfn=None):
    if event.get("source") != "aws.states" or event.get("detail-type") != "Step Functions Execution Status Change" or event.get("account") != account or event.get("region") != region:
        raise ValueError("UNTRUSTED_TERMINAL_EVENT")
    detail = event.get("detail") or {}
    if detail.get("status") not in {"FAILED", "TIMED_OUT", "ABORTED"}:
        raise ValueError("UNSUPPORTED_TERMINAL_STATE")
    stage = next((stage for stage, arn in machines.items() if arn and detail.get("stateMachineArn") == arn), None)
    if stage is None:
        raise ValueError("TERMINAL_WORKFLOW_NOT_ALLOWED")
    machine = detail["stateMachineArn"]
    prefix = machine.replace(":stateMachine:", ":execution:") + ":"
    execution = detail.get("executionArn")
    if not isinstance(execution, str) or not execution.startswith(prefix):
        raise ValueError("TERMINAL_EXECUTION_NOT_ALLOWED")
    name = execution[len(prefix):]
    match = re.fullmatch(r"(?:report-)?(inv-[0-9a-f]{32})", name)
    if not match:
        raise ValueError("TERMINAL_EXECUTION_CASE_UNKNOWN")
    if sfn is None: raise ValueError("TERMINAL_EXECUTION_VERIFICATION_REQUIRED")
    actual = sfn.describe_execution(executionArn=execution, includedData="METADATA_ONLY")
    if actual.get("executionArn") != execution or actual.get("stateMachineArn") != machine or actual.get("status") != detail["status"]:
        raise ValueError("TERMINAL_EXECUTION_STATUS_NOT_VERIFIED")
    return {"stage": stage, "case_id": match.group(1), "execution_arn": execution, "require_existing_case": stage == "PUBLICATION",
            "verified_terminal_state": detail["status"], "failure": {"Error": "STATES_EXECUTION_" + detail["status"]}}


def terminate(event, table, s3, *, registry=None, account=None, default_service_id=None,
              default_bucket=None, clock=time.time, lease_seconds=120, machine_arn=None):
    stage = event.get("stage")
    if stage not in STAGES:
        raise ValueError("INVALID_TERMINAL_STAGE")
    case_id = identify(event)
    store, case = CasePublicationStore(table), table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
    if event.get("require_existing_case") and not case:
        return {"state": "SKIPPED", "case_id": case_id, "reason": "SCOPED_CASE_NOT_CREATED"}
    if machine_arn:
        expected = machine_arn.replace(":stateMachine:", ":execution:") + ":" + case_id
        if event.get("execution_arn") != expected or case and case.get("workflow_execution_arn") != expected:
            raise ValueError("TERMINAL_WORKFLOW_EXECUTION_MISMATCH")
    elif case.get("workflow_execution_arn") and case["workflow_execution_arn"] != event.get("execution_arn"):
        raise ValueError("TERMINAL_WORKFLOW_EXECUTION_MISMATCH")
    service_id = validate_service(case.get("service_id") or event.get("service_id") or default_service_id)
    if event.get("service_id") not in (None, service_id):
        raise ValueError("TERMINAL_SERVICE_MISMATCH")
    if case and not case.get("service_id") and service_id != default_service_id:
        raise ValueError("TERMINAL_UNSCOPED_CASE_DENIED")
    if case.get("status") in FINISHED or case.get("status") == "AWAITING_APPROVAL" and stage in {"AI1", "AI2"}:
        return {"state": "SKIPPED", "case_id": case_id, "reason": "LATER_BUSINESS_STATE_EXISTS"}
    profile = None
    if registry is not None:
        from service_scope import resolve
        profile = resolve(registry, service_id, account=account)
    elif service_id != default_service_id:
        raise ValueError("SERVICE_REGISTRY_REQUIRED")
    bucket = case.get("dashboard_bucket") or (profile or {}).get("audit_bucket") or default_bucket
    if profile and profile.get("audit_bucket") and bucket != profile["audit_bucket"]:
        raise ValueError("TERMINAL_BUCKET_OUTSIDE_SERVICE")
    key = case.get("dashboard_key") or (case_id + ".md" if service_id == default_service_id else service_id + "/" + case_id + ".md")
    failures = error_fields(event)
    if not failures:
        failures = {"failure": {"Error": "UNCLASSIFIED_ERROR"}}
    code = failures["failure"]["Error"] if "failure" in failures else next(iter(failures.values()))["Error"]
    state = STAGES[stage]
    previous = case.get("dashboard_notification_outcome") or {}
    stamp = case.get("recorded_at") or previous.get("detail", {}).get("published_at") if case.get("status") == state and case.get("terminal_error_code") == code else None
    stamp = stamp or datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    summary = stage + " 처리 단계가 실패했습니다. 오류 코드: " + code + ". 수동 확인이 필요합니다."
    body = "# 처리 실패 리포트\n\n## 요약\n" + summary + "\n\n## 처리 상태\n자동 승인·차단·격리 작업을 이 실패 처리기에서 실행하지 않았습니다.\n"
    outbox = make_outbox(case_id, service_id, state, case.get("tier", 3), bucket, key, stamp,
                        summary=summary, recommended_action="none", failures=failures, target=case.get("target"), previous=previous)
    job = make_job(case_id, service_id, bucket, key, body, "OUTCOME", "dashboard_notification_outcome", outbox, int(clock()))
    fields = {"status": state, "terminal_stage": stage, "terminal_error_code": code, "recorded_at": stamp,
              "dashboard_bucket": bucket, "dashboard_key": key}
    if not case:
        fields.update(created_at=stamp, tier=3, recommended_action="none", target={})
        if machine_arn: fields["workflow_execution_arn"] = event["execution_arn"]
    return {"case_id": case_id, "service_id": service_id, **PublicationCoordinator(store, s3, clock=clock, lease_seconds=lease_seconds).submit(job, fields, allow_create=not bool(case))}


def handler(event, context):
    import boto3
    if event.get("source") == "aws.states":
        event = normalize_eventbridge(event, machines={"AI1": os.environ.get("AI1_STATE_MACHINE_ARN"), "AI2": os.environ.get("AI2_STATE_MACHINE_ARN"),
                                     "PUBLICATION": os.environ.get("PIPELINE_STATE_MACHINE_ARN")},
                                      account=os.environ["EXPECTED_ACCOUNT"], region=os.environ["AWS_REGION"], sfn=boto3.client("stepfunctions"))
    resource = boto3.resource("dynamodb")
    lease = max(120, int(context.get_remaining_time_in_millis() / 1000) + 30) if context else 120
    return terminate(event, resource.Table(os.environ["CASES_TABLE"]), boto3.client("s3"),
                     registry=resource.Table(os.environ["REGISTRY_TABLE"]) if os.environ.get("REGISTRY_TABLE") else None,
                     account=os.environ.get("EXPECTED_ACCOUNT"), default_service_id=os.environ.get("DEFAULT_SERVICE_ID"),
                     default_bucket=os.environ.get("DASHBOARD_BUCKET"), lease_seconds=min(900, lease), machine_arn=os.environ.get("PIPELINE_STATE_MACHINE_ARN"))
