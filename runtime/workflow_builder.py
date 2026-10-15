"""A service-bound Standard workflow. Real qualified Lambda ARNs are required."""
import re

FUNCTION = re.compile(r"arn:aws(?:-us-gov|-cn)?:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\Z")
REQUIRED = {"pipeline", "blocker", "terminal"}
TRANSIENT = [{"ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
              "IntervalSeconds": 2, "BackoffRate": 2, "MaxAttempts": 4}]
PUBLICATION_RETRY = [{"ErrorEquals": ["PublicationBusy", "ClientError"], "IntervalSeconds": 5, "BackoffRate": 2, "MaxAttempts": 6}, *TRANSIENT]


def definition(functions, *, dry_run=True, substitutions=False):
    if set(functions) != REQUIRED or type(dry_run) is not bool:
        raise ValueError("INVALID_WORKFLOW_CONFIGURATION")
    for value in functions.values():
        if not isinstance(value, str) or not (FUNCTION.fullmatch(value) or substitutions and re.fullmatch(r"\$\{[A-Za-z][A-Za-z0-9]*\}", value)):
            raise ValueError("QUALIFIED_FUNCTION_ARN_REQUIRED")

    def task(function, payload, result, *, next_state=None, end=False, retry=None, catch=None, timeout=120, callback=False):
        state = {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke" + (".waitForTaskToken" if callback else ""),
                 "Parameters": {"FunctionName": functions[function], "Payload": payload}, "TimeoutSeconds": timeout, "ResultPath": result}
        if not callback and result is not None:
            state["ResultSelector"] = {"result.$": "$.Payload"}
        if retry:
            state["Retry"] = retry
        if catch:
            state["Catch"] = catch
        state.update({"End": True} if end else {"Next": next_state})
        return state

    scoped = {"case_id.$": "$.prepared.result.case_id", "service_id.$": "$.prepared.result.service_id"}
    execution = {"execution_arn.$": "$$.Execution.Id"}
    failure = lambda target: [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": target}]
    states = {}
    states["PrepareCase"] = task("pipeline", {"stage": "prepare", "signal.$": "$.signal", "dry_run.$": "$.dry_run", **execution}, "$.prepared",
        next_state="RouteCase", retry=PUBLICATION_RETRY, catch=failure("PreparationFailed"))
    states["RouteCase"] = {"Type": "Choice", "Choices": [{"Variable": "$.prepared.result.tier", "NumericEquals": 1, "Next": "AutomaticBlock"}], "Default": "PublishAndWait"}
    states["PublishAndWait"] = task("pipeline", {"stage": "wait_approval", **scoped, **execution, "TaskToken.$": "$$.Task.Token"}, "$.approval",
        next_state="Decision", callback=True, timeout=14400, retry=PUBLICATION_RETRY,
        catch=[{"ErrorEquals": ["States.Timeout"], "ResultPath": "$.failure", "Next": "RecordTimedOut"}, *failure("ApprovalFailed")])
    states["Decision"] = {"Type": "Choice", "Choices": [
        {"Variable": "$.approval.decision", "StringEquals": "reject", "Next": "RecordRejected"},
        {"Variable": "$.approval.decision", "StringEquals": "approve", "Next": "VerifyApprovalCommit"}], "Default": "RecordApprovalUnconfirmed"}
    states["VerifyApprovalCommit"] = task("pipeline", {"stage": "approval_ready", **scoped, **execution}, "$.commit", next_state="ApprovalCommit", retry=TRANSIENT, catch=failure("ApprovalFailed"))
    states["ApprovalCommit"] = {"Type": "Choice", "Choices": [
        {"And": [{"Variable": "$.commit.result.ready", "BooleanEquals": True}, {"Variable": "$.commit.result.approved_action", "StringEquals": "block_ip"}], "Next": "ApprovedBlock"},
        {"Variable": "$.commit.result.ready", "BooleanEquals": True, "Next": "RecordNoAction"},
        {"Variable": "$.commit.result.keep_waiting", "BooleanEquals": True, "Next": "WaitForCommit"}], "Default": "RecordApprovalUnconfirmed"}
    states["WaitForCommit"] = {"Type": "Wait", "Seconds": 2, "Next": "VerifyApprovalCommit"}
    for name, human, result_name, failed in (("AutomaticBlock", False, "RecordAutomaticResult", "RecordAutomaticFailure"),
                                            ("ApprovedBlock", True, "RecordApprovedResult", "RecordApprovedFailure")):
        states[name] = task("blocker", {**scoped, "attacker_ip.$": "$.prepared.result.target.source_ip", "dry_run.$": "$.prepared.result.dry_run",
                            "human_approved": human, "operation_id.$": "$$.Execution.Id"}, "$.block",
                            next_state=result_name, timeout=180, retry=TRANSIENT, catch=failure(failed))
    finals = {"RecordAutomaticResult": ("AUTO_BLOCK_RESULT", "HOTL", True, False), "RecordAutomaticFailure": ("AUTO_BLOCK_FAILED", "HOTL", False, True),
              "RecordApprovedResult": ("BLOCK_RESULT", "HITL", True, False), "RecordApprovedFailure": ("BLOCK_FAILED", "HITL", False, True),
              "RecordTimedOut": ("TIMED_OUT", "HITL", False, True), "RecordRejected": ("REJECTED", "HITL", False, False),
              "RecordNoAction": ("NO_ACTION", "HITL", False, False), "RecordApprovalUnconfirmed": ("APPROVAL_FAILED", "HITL", False, False)}
    for name, (outcome, mode, response, failed) in finals.items():
        payload = {"stage": "record", **scoped, **execution, "outcome": outcome, "mode": mode}
        if response:
            payload["response.$"] = "$.block.result"
        if failed:
            payload["failure.$"] = "$.failure"
        states[name] = task("pipeline", payload, "$.recorded", end=True, retry=PUBLICATION_RETRY, catch=failure("PublicationFailed"))
    for name, stage in (("PreparationFailed", "AI1"), ("ApprovalFailed", "APPROVAL"), ("PublicationFailed", "PUBLICATION")):
        # No callback token/input/Cause is logged by the terminal function. It
        # selects Error and loads only this case's private scoped publication.
        states[name] = task("terminal", {"stage": stage, "case_id.$": "$$.Execution.Name",
            "service_id.$": "$$.Execution.Input.signal.detail.service_id", "failure.$": "$.failure", **execution}, "$.terminal",
            end=True, retry=PUBLICATION_RETRY)
    return {"Comment": "Service-bound HOTL and HITL with durable publications and committed human approvals",
            "StartAt": "PrepareCase", "TimeoutSeconds": 18000, "States": states}


def build_workflow(function_arns, *, default_dry_run=True):
    return definition(function_arns, dry_run=default_dry_run)


def cfn_workflow(default_dry_run=True):
    return definition({"pipeline": "${PipelineFunctionArn}", "blocker": "${BlockerFunctionArn}", "terminal": "${TerminalFunctionArn}"},
                      dry_run=default_dry_run, substitutions=True)
