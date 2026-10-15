"""Pure changes for legacy workflow failure branches; no deployment calls."""
import copy


def terminal_state(function_arn, stage, *, case_path=None, report_path="$.report", service_path=None):
    payload = {"stage": stage, "failure.$": "$.pipeline_failure", "execution_arn.$": "$$.Execution.Id"}
    if case_path:
        payload["case_id.$"] = case_path
    elif report_path:
        payload["report.$"] = report_path
    if service_path:
        payload["service_id.$"] = service_path
    return {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": function_arn, "Payload": payload},
            "ResultPath": None, "Retry": [{"ErrorEquals": ["Lambda.ServiceException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
                                           "IntervalSeconds": 2, "MaxAttempts": 3, "BackoffRate": 2}], "End": True}


def catch_to(state, name):
    catches = state.setdefault("Catch", [])
    # Preserve specific catches such as approval timeout; States.ALL must be
    # last and cannot share ErrorEquals with another error.
    catches[:] = [item for item in catches if item.get("ErrorEquals") != ["States.ALL"]]
    catches.append({"ErrorEquals": ["States.ALL"], "ResultPath": "$.pipeline_failure", "Next": name})


def patch_ai1_workflow(definition, terminal_function_arn, *, service_path=None):
    result = copy.deepcopy(definition)
    states = result["States"]
    if "Triage" not in states:
        raise ValueError("EXPECTED_AI1_TRIAGE_STATE_MISSING")
    catch_to(states["Triage"], "RecordAI1Failure")
    states["RecordAI1Failure"] = terminal_state(terminal_function_arn, "AI1", service_path=service_path)
    if "Block" in states:
        states["Block"]["ResultSelector"] = {"result.$": "$.Payload"}
    for name in ("RecordBlocked", "RecordBlockFailed"):
        if name in states:
            states[name]["Parameters"]["Payload"]["outcome"] = "AUTO_BLOCK_RESULT" if name == "RecordBlocked" else "AUTO_BLOCK_FAILED"
    return result


def patch_ai2_workflow(definition, terminal_function_arn, *, service_path=None):
    result = copy.deepcopy(definition)
    states = result["States"]
    if "Investigate" not in states or "PublishAndWait" not in states:
        raise ValueError("EXPECTED_AI2_STATES_MISSING")
    catch_to(states["Investigate"], "RecordAI2Failure")
    catch_to(states["PublishAndWait"], "RecordApprovalFailure")
    states["RecordAI2Failure"] = terminal_state(terminal_function_arn, "AI2", case_path="$.case_id", service_path=service_path)
    states["RecordApprovalFailure"] = terminal_state(terminal_function_arn, "APPROVAL", case_path="$.case_id", service_path=service_path)
    return result


def publication_indexes():
    return [{"IndexName": name, "KeySchema": [{"AttributeName": state, "KeyType": "HASH"}, {"AttributeName": retry, "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "KEYS_ONLY"}}
            for name, state, retry in [("PublicationStateIndex", "publication_state", "publication_retry_at"),
                                       ("NotificationStateIndex", "notification_state", "notification_retry_at")]]
