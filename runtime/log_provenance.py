"""Verify subscription pointers against stored same-region CloudWatch events."""
import hashlib
import re


def verify_stored_logs(payload, rows, logs):
    if logs is None: raise ValueError("STORED_LOG_VERIFICATION_REQUIRED")
    stream = payload.get("logStream")
    if not isinstance(stream, str) or not re.fullmatch(r"[^\x00-\x1f:*]{1,512}", stream):
        raise ValueError("INVALID_PROVIDER_LOG_STREAM")
    expected = {}
    for row in rows:
        identifier, stamp, message = row.get("id"), row.get("timestamp"), row.get("message")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 256 or type(stamp) is not int or not 0 < stamp < 2 ** 53 or not isinstance(message, str):
            raise ValueError("INVALID_PROVIDER_LOG_POINTER")
        value = (stamp, hashlib.sha256(message.encode()).hexdigest())
        if identifier in expected and expected[identifier] != value:
            raise ValueError("CONFLICTING_PROVIDER_LOG_IDENTITY")
        expected[identifier] = value
    if not expected: return
    arguments = {"logGroupName": payload["logGroup"], "logStreamNames": [stream], "startTime": min(value[0] for value in expected.values()),
        "endTime": max(value[0] for value in expected.values()) + 1, "limit": 10000}
    verified, tokens = set(), set()
    for _ in range(32):
        response = logs.filter_log_events(**arguments)
        for item in response.get("events", []):
            identifier = item.get("eventId")
            if identifier not in expected: continue
            message = item.get("message")
            if (item.get("logStreamName") != stream or not isinstance(message, str)
                    or (item.get("timestamp"), hashlib.sha256(message.encode()).hexdigest()) != expected[identifier]):
                raise ValueError("STORED_PROVIDER_LOG_CONTENT_MISMATCH")
            verified.add(identifier)
        if verified == set(expected): return
        token = response.get("nextToken")
        if not token: break
        if token in tokens: raise ValueError("STORED_PROVIDER_LOG_PAGINATION_INCOMPLETE")
        tokens.add(token)
        arguments["nextToken"] = token
    raise ValueError("STORED_PROVIDER_LOG_EVENT_NOT_FOUND")
