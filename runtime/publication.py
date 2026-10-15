"""Conditional, durable S3 publication; only its selected outbox reaches Slack.

The private case journal may hold report text until S3 accepts it. The stream
relay must continue projecting only dashboard_notification_* attributes.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
import time
import uuid
from outcome_metadata import CASE, safe_code, validate_service


class PublicationBusy(RuntimeError):
    pass


def conditional(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def error_code(error):
    response = getattr(error, "response", {})
    code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
    return safe_code(code) or safe_code(type(error).__name__) or "PUBLICATION_DEPENDENCY_FAILED"


def make_job(case_id, service_id, bucket, key, body, phase, outbox_attribute, outbox, now):
    validate_service(service_id)
    if not isinstance(case_id, str) or not CASE.fullmatch(case_id):
        raise ValueError("INVALID_PUBLICATION_CASE")
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ValueError("INVALID_PUBLICATION_BUCKET")
    if key != service_id + "/" + case_id + ".md" and not (service_id == "legacy-whs" and key == case_id + ".md"):
        raise ValueError("INVALID_PUBLICATION_KEY")
    if not isinstance(body, str) or not 0 < len(body.encode("utf-8")) <= 65536:
        raise ValueError("INVALID_PUBLICATION_DOCUMENT")
    if phase not in {"INITIAL", "OUTCOME"} or outbox_attribute not in {
        "dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome",
    }:
        raise ValueError("INVALID_PUBLICATION_PHASE")
    if not isinstance(outbox, dict) or not isinstance(outbox.get("event_id"), str):
        raise ValueError("INVALID_PUBLICATION_OUTBOX")
    body_sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    revision = hashlib.sha256(json.dumps([service_id, case_id, phase, outbox["event_id"], body_sha], separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "1.0", "case_id": case_id, "service_id": service_id,
            "revision": revision, "body_sha256": body_sha, "state": "PENDING", "phase": phase,
            "bucket": bucket, "key": key, "body": body, "outbox_attribute": outbox_attribute,
            "outbox": outbox, "created_at": int(now), "attempts": 0}


class CasePublicationStore:
    def __init__(self, table):
        self.table = table

    def get(self, case_id):
        return self.table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}

    def prepare(self, job, fields, now, *, allow_create=False):
        case_id, service = job["case_id"], job["service_id"]
        previous = self.get(case_id)
        if not previous and not allow_create:
            raise ValueError("PUBLICATION_CASE_MISSING")
        if previous.get("service_id") not in (None, service):
            raise ValueError("PUBLICATION_SERVICE_MISMATCH")
        old = previous.get("dashboard_publication") or {}
        if old.get("revision") == job["revision"]:
            return old
        if old.get("phase") == "OUTCOME" and job["phase"] == "INITIAL":
            return {"state": "STALE", "revision": old.get("revision")}
        if old.get("state") == "PUBLISHING" and int(old.get("lease_until", 0)) > now:
            raise PublicationBusy("PUBLICATION_LEASE_BUSY")
        forbidden = {"case_id", "dashboard_publication", "publication_revision", "publication_state", "publication_retry_at", "service_id",
                     "dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome"}
        if forbidden.intersection(fields):
            raise ValueError("INVALID_PUBLICATION_CASE_FIELDS")
        selected = {**fields, "updated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), "service_id": service, "dashboard_publication": job,
                    "publication_revision": job["revision"], "publication_state": "PENDING",
                    "publication_retry_at": int(now), "publication_updated_at": int(now)}
        names, values, setters = {"#service": "service_id", "#revision": "publication_revision",
                                   "#job": "dashboard_publication", "#lease": "lease_until"}, {":service": service, ":now": int(now)}, []
        for index, (name, value) in enumerate(selected.items()):
            alias, token = "#f" + str(index), ":v" + str(index)
            names[alias], values[token] = name, value
            setters.append(alias + " = " + token)
        expression = "(attribute_not_exists(#service) OR #service = :service) AND (attribute_not_exists(#job.#lease) OR #job.#lease <= :now)"
        if old.get("revision"):
            values[":previous"] = old["revision"]
            expression += " AND #revision = :previous"
        else:
            expression += " AND attribute_not_exists(#revision)"
        if not allow_create:
            expression += " AND attribute_exists(case_id)"
        try:
            self.table.update_item(Key={"case_id": case_id}, UpdateExpression="SET " + ", ".join(setters),
                                  ConditionExpression=expression, ExpressionAttributeNames=names, ExpressionAttributeValues=values)
        except Exception as error:
            if conditional(error):
                raise PublicationBusy("PUBLICATION_PREPARE_CONFLICT") from None
            raise
        return job

    def claim(self, case_id, revision, service_id, owner, now, lease):
        try:
            self.table.update_item(Key={"case_id": case_id},
                UpdateExpression="SET #job.#state = :publishing, #job.#owner = :owner, #job.#lease = :lease, publication_retry_at = :lease, publication_updated_at = :now",
                ConditionExpression="publication_revision = :revision AND service_id = :service AND publication_state = :pending AND (attribute_not_exists(#job.#lease) OR #job.#lease <= :now) AND publication_retry_at <= :now",
                ExpressionAttributeNames={"#job": "dashboard_publication", "#state": "state", "#owner": "owner", "#lease": "lease_until"},
                ExpressionAttributeValues={":publishing": "PUBLISHING", ":pending": "PENDING", ":owner": owner,
                    ":lease": int(now + lease), ":now": int(now), ":revision": revision, ":service": service_id})
            return True
        except Exception as error:
            if conditional(error):
                return False
            raise

    def complete(self, job, owner, now):
        names = {"#job": "dashboard_publication", "#state": "state", "#owner": "owner", "#lease": "lease_until", "#body": "body"}
        values = {":published": "PUBLISHED", ":publishing": "PUBLISHING", ":owner": owner,
                  ":revision": job["revision"], ":service": job["service_id"], ":now": int(now)}
        update = "SET publication_state = :published, #job.#state = :published, #job.published_at = :now, publication_updated_at = :now"
        if job.get("emit_notifications", True):
            names["#outbox"] = job["outbox_attribute"]
            values.update({":outbox": job["outbox"], ":pending": "PENDING"})
            update += ", #outbox = :outbox, notification_state = :pending, notification_retry_at = :now"
        update += " REMOVE #job.#body, #job.#owner, #job.#lease"
        self.table.update_item(Key={"case_id": job["case_id"]},
            UpdateExpression=update,
            ConditionExpression="publication_revision = :revision AND service_id = :service AND #job.#owner = :owner AND #job.#state = :publishing",
            ExpressionAttributeNames=names, ExpressionAttributeValues=values)

    def retry(self, job, owner, now, code, delay):
        self.table.update_item(Key={"case_id": job["case_id"]},
            UpdateExpression="SET #job.#state = :pending, #job.last_error_code = :code, publication_retry_at = :retry, publication_updated_at = :now, #job.attempts = if_not_exists(#job.attempts, :zero) + :one REMOVE #job.#owner, #job.#lease",
            ConditionExpression="publication_revision = :revision AND service_id = :service AND #job.#owner = :owner",
            ExpressionAttributeNames={"#job": "dashboard_publication", "#state": "state", "#owner": "owner", "#lease": "lease_until"},
            ExpressionAttributeValues={":pending": "PENDING", ":owner": owner, ":revision": job["revision"], ":service": job["service_id"],
                ":now": int(now), ":retry": int(now + delay), ":code": safe_code(code) or "PUBLICATION_DEPENDENCY_FAILED", ":zero": 0, ":one": 1})

    def pending(self, now, *, index_name="PublicationStateIndex", limit=25, cursor=None):
        arguments = {"IndexName": index_name, "KeyConditionExpression": "publication_state = :pending AND publication_retry_at <= :now",
                     "ExpressionAttributeValues": {":pending": "PENDING", ":now": int(now)},
                     "ProjectionExpression": "case_id", "Limit": min(max(int(limit), 1), 100)}
        if cursor:
            arguments["ExclusiveStartKey"] = cursor
        result = self.table.query(**arguments)
        return result.get("Items", []), result.get("LastEvaluatedKey")


class PublicationCoordinator:
    def __init__(self, store, s3, *, clock=time.time, lease_seconds=120, retry_delay=60):
        self.store, self.s3, self.clock = store, s3, clock
        self.lease_seconds, self.retry_delay = int(lease_seconds), int(retry_delay)
        if not 30 <= self.lease_seconds <= 900 or not 1 <= self.retry_delay <= 3600:
            raise ValueError("INVALID_PUBLICATION_RETRY_CONFIGURATION")

    def submit(self, job, fields, *, allow_create=False):
        prepared = self.store.prepare(job, fields, int(self.clock()), allow_create=allow_create)
        if prepared.get("state") in {"PUBLISHED", "STALE"}:
            return {"state": prepared["state"], "revision": prepared.get("revision")}
        return self.deliver(job["case_id"])

    def deliver(self, case_id):
        case = self.store.get(case_id)
        job = case.get("dashboard_publication") or {}
        if not job or job.get("state") == "PUBLISHED":
            return {"state": "PUBLISHED" if job else "ABSENT", "revision": job.get("revision")}
        if job.get("service_id") != case.get("service_id"):
            raise ValueError("PUBLICATION_SERVICE_MISMATCH")
        owner, now = uuid.uuid4().hex, int(self.clock())
        if not self.store.claim(case_id, job["revision"], job["service_id"], owner, now, self.lease_seconds):
            return {"state": "PENDING", "revision": job["revision"], "error_code": "PUBLICATION_LEASE_BUSY"}
        try:
            if hashlib.sha256(job["body"].encode("utf-8")).hexdigest() != job["body_sha256"]:
                raise ValueError("PUBLICATION_DOCUMENT_DIGEST_MISMATCH")
            self.s3.put_object(Bucket=job["bucket"], Key=job["key"], Body=job["body"].encode("utf-8"),
                               ContentType="text/markdown; charset=utf-8",
                               Metadata={"publication-revision": job["revision"], "service-id": job["service_id"]})
            self.store.complete(job, owner, int(self.clock()))
            return {"state": "PUBLISHED", "revision": job["revision"]}
        except Exception as error:
            # A timed-out commit may already have succeeded. Observe it before
            # queueing another attempt; do not clear a newer owner's lease.
            observed = self.store.get(case_id).get("dashboard_publication") or {}
            if observed.get("revision") == job["revision"] and observed.get("state") == "PUBLISHED":
                return {"state": "PUBLISHED", "revision": job["revision"]}
            code = error_code(error)
            try:
                self.store.retry(job, owner, int(self.clock()), code, self.retry_delay)
            except Exception:
                pass  # Expired leases remain discoverable through the sparse GSI.
            return {"state": "PENDING", "revision": job["revision"], "error_code": code}
