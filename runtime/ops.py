"""Operational alarm reporting, separately authenticated from report events."""
import hashlib
import json
import os
import re
import time
import uuid

from .expected_activity import wrap


def selected(event, topic):
    records = event.get("Records", []) if isinstance(event, dict) else []
    if not isinstance(records, list) or len(records) > 10:
        raise ValueError("INVALID_OPERATIONAL_BATCH")
    items = []
    for row in records:
        sns = row.get("Sns", {})
        if row.get("EventSource") != "aws:sns" or sns.get("TopicArn") != topic:
            raise ValueError("UNTRUSTED_OPERATIONAL_SOURCE")
        message = json.loads(sns.get("Message", "{}"))
        if not isinstance(message, dict): raise ValueError("INVALID_OPERATIONAL_EVENT")
        if message.get("NewStateValue") in {"ALARM", "OK", "INSUFFICIENT_DATA"}:
            alarm = message.get("AlarmName", "운영 지표")
            if not isinstance(alarm, str) or not re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,255}", alarm): alarm = "운영 지표"
            # CloudWatch reasons and metric dimensions may contain sensitive
            # application content; they are not forwarded.
            lines = ["[보안 아키텍처 운영 알림]", "지표: " + alarm, "상태: " + message["NewStateValue"],
                     "확인: AWS CloudWatch 알람과 관리자 대시보드에서 확인하세요."]
        elif message.get("schema_version") == "1.0" and message.get("event") in {"UNATTRIBUTED_SECURITY_SIGNAL", "SERVICE_ONBOARDING_REVIEW_REQUIRED", "CASE_BUDGET_LIMITED"}:
            reason = message.get("reason_code", "MANUAL_REVIEW_REQUIRED")
            reason = reason if isinstance(reason, str) and re.fullmatch(r"[A-Z0-9_]{1,100}", reason) else "MANUAL_REVIEW_REQUIRED"
            lines = ["[보안 아키텍처 운영 알림]", "항목: " + message["event"], "확인 코드: " + reason,
                     "확인: 등록부와 제한된 감사 기록을 검토하세요."]
        else:
            continue
        identifier = sns.get("MessageId")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,128}", identifier):
            raise ValueError("INVALID_OPERATIONAL_IDENTITY")
        items.append(("ops#" + hashlib.sha256(f"{topic}:{identifier}".encode()).hexdigest(), "\n".join(lines)))
    return items


def deliver(identifier, text, *, table, slack, channel):
    owner, now = uuid.uuid4().hex, int(time.time())
    prior = table.get_item(Key={"notification_id": identifier}, ConsistentRead=True).get("Item", {})
    if prior.get("status") == "SENT": return "DUPLICATE"
    if prior.get("status") in {"SENDING", "UNKNOWN"}: return "REVIEW_REQUIRED"
    reply = None
    try:
        table.put_item(Item={"notification_id": identifier, "status": "SENDING", "owner": owner,
                            "channel": channel, "created_at": now}, ConditionExpression="attribute_not_exists(notification_id)")
    except Exception as error:
        if getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException": return "IN_PROGRESS"
        raise
    try:
        reply = slack.call("chat.postMessage", {"channel": channel, "text": text, "mrkdwn": False,
                           "unfurl_links": False, "unfurl_media": False, "parse": "none"})
        table.update_item(Key={"notification_id": identifier}, UpdateExpression="SET #s = :sent, ts = :ts REMOVE #o",
            ConditionExpression="#o = :owner", ExpressionAttributeNames={"#s": "status", "#o": "owner"},
            ExpressionAttributeValues={":sent": "SENT", ":ts": reply["ts"], ":owner": owner})
        return "POSTED"
    except Exception:
        observed = table.get_item(Key={"notification_id": identifier}, ConsistentRead=True).get("Item", {})
        if (reply and observed.get("status") == "SENT" and observed.get("channel") == channel
                and observed.get("ts") == reply.get("ts")):
            return "POSTED"
        # Never automatically duplicate a possibly posted operational alarm.
        try:
            table.update_item(Key={"notification_id": identifier}, UpdateExpression="SET #s = :unknown REMOVE #o",
                ConditionExpression="#o = :owner", ExpressionAttributeNames={"#s": "status", "#o": "owner"},
                ExpressionAttributeValues={":unknown": "UNKNOWN", ":owner": owner})
        except Exception:
            pass  # SENDING is also held for manual recovery; never repost.
        raise RuntimeError("OPERATIONAL_DELIVERY_REQUIRES_REVIEW") from None


def handler(event, context):
    from .notifier import Slack, Config, get_token
    import boto3
    items = selected(event, os.environ["OPS_TOPIC_ARN"])
    # SNS remains the durable operational destination even when Slack has not
    # been configured by this company's installer.
    if os.environ.get("NOTIFICATIONS_ENABLED", "false") != "true":
        return {"notifications": "SNS_ONLY", "count": len(items)}
    cfg = Config(account=os.environ["EXPECTED_ACCOUNT"], region=os.environ["AWS_REGION"],
                 channel=os.environ["SLACK_CHANNEL_ID"], secret_arn=os.environ["SLACK_SECRET_ARN"],
                 dashboard_bucket=os.environ["AUDIT_BUCKET"])
    token = get_token(wrap(boto3.client("secretsmanager"), context), cfg)
    table = boto3.resource("dynamodb").Table(os.environ["NOTIFICATIONS_TABLE"])
    result = [deliver(key, text, table=table, slack=Slack(token), channel=cfg.channel) for key, text in items]
    print(json.dumps({"event": "OPERATIONAL_NOTIFICATION", "results": result}))
    return {"results": result}
