"""Scheduled recovery for publication and outbox leases, using sparse indexes."""
import math
import os
import time
from publication import CasePublicationStore, PublicationCoordinator
from outbox_delivery import publish_case


def reconcile(table, s3, events, bus, *, clock=time.time, publication_index="PublicationStateIndex",
              notification_index="NotificationStateIndex", limit=25, max_pages=2, lease_seconds=120):
    store = CasePublicationStore(table)
    coordinator = PublicationCoordinator(store, s3, clock=clock, lease_seconds=lease_seconds)
    counts = {"publication_examined": 0, "published": 0, "publication_pending": 0,
              "notification_examined": 0, "notification_pending": 0, "errors": 0}
    cursor = None
    for _ in range(max_pages):
        rows, cursor = store.pending(int(clock()), index_name=publication_index, limit=limit, cursor=cursor)
        for row in rows:
            counts["publication_examined"] += 1
            try:
                outcome = coordinator.deliver(row["case_id"])
                counts["published" if outcome["state"] == "PUBLISHED" else "publication_pending"] += 1
            except Exception:
                counts["errors"] += 1
        if not cursor:
            break
    cursor = None
    for _ in range(max_pages):
        arguments = {"IndexName": notification_index,
                     "KeyConditionExpression": "notification_state = :pending AND notification_retry_at <= :now",
                     "ExpressionAttributeValues": {":pending": "PENDING", ":now": int(clock())},
                     "ProjectionExpression": "case_id", "Limit": min(max(int(limit), 1), 100)}
        if cursor:
            arguments["ExclusiveStartKey"] = cursor
        page = table.query(**arguments)
        for row in page.get("Items", []):
            counts["notification_examined"] += 1
            try:
                outcomes = publish_case(row["case_id"], table, events, bus, clock=clock, lease_seconds=lease_seconds)
                if any(state == "BUSY" for state in outcomes.values()):
                    counts["notification_pending"] += 1
            except Exception:
                counts["notification_pending"] += 1
                counts["errors"] += 1
        cursor = page.get("LastEvaluatedKey")
        if not cursor:
            break
    return counts


def handler(event, context):
    import boto3
    remaining = context.get_remaining_time_in_millis() if context is not None else 90000
    lease = min(900, max(120, math.ceil(remaining / 1000) + 30))
    counts = reconcile(boto3.resource("dynamodb").Table(os.environ["CASES_TABLE"]), boto3.client("s3"),
                     boto3.client("events"), os.environ["NOTIFICATION_BUS"],
                     publication_index=os.environ.get("PUBLICATION_INDEX", "PublicationStateIndex"),
                     notification_index=os.environ.get("NOTIFICATION_INDEX", "NotificationStateIndex"),
                     limit=int(os.environ.get("RECONCILE_BATCH_SIZE", "25")), lease_seconds=lease)
    # Dependency failures are intentionally durable PENDING results. Publish
    # bounded counters so repeated failures are still visible to operations.
    emit_metrics(boto3.client("cloudwatch"), counts, os.environ["AWS_LAMBDA_FUNCTION_NAME"])
    return counts


def emit_metrics(cloudwatch, counts, function_name):
    pending = sum(int(counts.get(name, 0)) for name in ("publication_pending", "notification_pending"))
    errors = int(counts.get("errors", 0))
    cloudwatch.put_metric_data(Namespace="EnterpriseSecurity/Recovery", MetricData=[
        {"MetricName": name, "Dimensions": [{"Name": "FunctionName", "Value": function_name}], "Value": max(0, value), "Unit": "Count"}
        for name, value in (("PendingExamined", pending), ("DependencyErrors", errors))])
