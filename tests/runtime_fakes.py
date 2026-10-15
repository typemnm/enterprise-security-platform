"""A conditional DynamoDB SDK test double, plus controlled dependency failures."""
import copy
import re


class ClientError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class MemoryTable:
    def __init__(self, items=None):
        self.items = copy.deepcopy(items or {})
        self.calls, self.history = [], []
        self.fail_complete = False
        self.complete_then_raise = False
        self.fail_outbox_ack = False
        self.on_update = None

    def get_item(self, **kwargs):
        self.calls.append(("get_item", kwargs))
        return {"Item": copy.deepcopy(self.items.get(kwargs["Key"]["case_id"], {}))}

    def conditional(self, test):
        if not test:
            raise ClientError("ConditionalCheckFailedException")

    def update_item(self, **kwargs):
        self.calls.append(("update_item", copy.deepcopy(kwargs)))
        names, values = kwargs.get("ExpressionAttributeNames", {}), kwargs.get("ExpressionAttributeValues", {})
        text = kwargs["UpdateExpression"] + " " + kwargs.get("ConditionExpression", "")
        for name in names:
            if name not in re.findall(r"#[A-Za-z0-9_]+", text):
                raise AssertionError("Unused DynamoDB expression name " + name)
        for value in values:
            if value not in re.findall(r":[A-Za-z0-9_]+", text):
                raise AssertionError("Unused DynamoDB expression value " + value)
        self.conditional(" ADD #job." not in text)
        case_id = kwargs["Key"]["case_id"]
        existing = self.items.get(case_id, {})
        case = self.items.setdefault(case_id, {"case_id": case_id})
        job = case.get("dashboard_publication") or {}
        update = kwargs["UpdateExpression"]
        if "#f0" in update:
            if "attribute_exists(case_id)" in kwargs["ConditionExpression"]:
                self.conditional(bool(existing))
            self.conditional(case.get("service_id") in (None, values[":service"]))
            self.conditional(int(job.get("lease_until", 0)) <= values[":now"])
            self.conditional(case.get("publication_revision") == values.get(":previous"))
            for alias, field in names.items():
                if alias.startswith("#f"):
                    case[field] = copy.deepcopy(values[":v" + alias[2:]])
        elif "#job.#state = :publishing" in update:
            self.conditional(case.get("publication_revision") == values[":revision"] and case.get("service_id") == values[":service"])
            self.conditional(case.get("publication_state") == "PENDING" and case.get("publication_retry_at", 0) <= values[":now"])
            self.conditional(job.get("lease_until", 0) <= values[":now"])
            job.update(state="PUBLISHING", owner=values[":owner"], lease_until=values[":lease"])
            case.update(publication_retry_at=values[":lease"], publication_updated_at=values[":now"])
        elif ":published" in values:
            self.conditional(case.get("publication_revision") == values[":revision"] and case.get("service_id") == values[":service"] and job.get("owner") == values[":owner"])
            if self.fail_complete:
                raise ClientError("ProvisionedThroughputExceededException")
            job.update(state="PUBLISHED", published_at=values[":now"])
            for key in ("body", "owner", "lease_until"):
                job.pop(key, None)
            case.update(publication_state="PUBLISHED", publication_updated_at=values[":now"])
            if ":outbox" in values:
                case[names["#outbox"]] = copy.deepcopy(values[":outbox"])
                case.update(notification_state="PENDING", notification_retry_at=values[":now"])
            if self.complete_then_raise:
                raise ClientError("RequestTimeout")
        elif "#job.#state = :pending" in update:
            self.conditional(case.get("publication_revision") == values[":revision"] and case.get("service_id") == values[":service"] and job.get("owner") == values[":owner"])
            job.update(state="PENDING", last_error_code=values[":code"], attempts=job.get("attempts", 0) + 1)
            for key in ("owner", "lease_until"):
                job.pop(key, None)
            case.update(publication_retry_at=values[":retry"], publication_updated_at=values[":now"])
        elif "#outbox" in names:
            outbox = case.get(names["#outbox"]) or {}
            self.conditional(case.get("service_id") == values[":service"] and outbox.get("event_id") == values[":event"])
            if "delivery_owner = :owner" in update:
                self.conditional(outbox.get("status") == "PENDING" or outbox.get("status") == "EMITTING" and outbox.get("delivery_lease_until", 0) <= values[":now"])
                self.conditional(outbox.get("delivery_retry_at", 0) <= values[":now"])
                outbox.update(status="EMITTING", delivery_owner=values[":owner"], delivery_lease_until=values[":lease"])
                case["notification_retry_at"] = values[":lease"]
            elif ":emitted" in values:
                self.conditional(outbox.get("delivery_owner") == values[":owner"] and outbox.get("status") == "EMITTING")
                if self.fail_outbox_ack:
                    raise ClientError("RequestTimeout")
                outbox.update(status="EMITTED", emitted_at=values[":now"])
                for key in ("delivery_owner", "delivery_lease_until", "delivery_retry_at"):
                    outbox.pop(key, None)
            else:
                self.conditional(outbox.get("delivery_owner") == values[":owner"])
                outbox.update(status="PENDING", delivery_error_code=values[":code"], delivery_retry_at=values[":retry"])
                outbox.pop("delivery_owner", None)
                outbox.pop("delivery_lease_until", None)
                case["notification_retry_at"] = values[":retry"]
        elif "notification_state = :state" in update:
            for alias, field in names.items():
                if alias.startswith("#o"):
                    expected = values.get(":e" + alias[2:])
                    self.conditional((case.get(field) or {}).get("event_id") == expected)
                    self.conditional((case.get(field) or {}).get("status") == values.get(":s" + alias[2:]))
            case.update(notification_state=values[":state"], notification_retry_at=values[":now"])
        elif update.startswith("SET task_token"):
            self.conditional(case.get("service_id") == values[":service"] and case.get("status") == values[":awaiting"] and not case.get("decision"))
            case.update(task_token=values[":token"], approval_expires_at=values[":expires"])
        elif "callback_status = :sending" in update:
            self.conditional(case.get("service_id") == values[":service"] and case.get("status") == values[":awaiting"] and not case.get("decision")
                and case.get("task_token") == values[":token"] and case.get("approval_expires_at", values[":now"] + 1) > values[":now"])
            case.update(decision=values[":decision"], decided_by=values[":user"], decision_reason=values[":reason"], decided_at=values[":at"],
                status=values[":decided"], approved_action=values[":action"], callback_status="SENDING", callback_owner=values[":owner"])
        elif "callback_status = :sent" in update or "callback_status = :state" in update:
            self.conditional(case.get("service_id") == values[":service"] and case.get("callback_owner") == values[":owner"] and case.get("decision") == values[":decision"])
            case["callback_status"] = values.get(":sent", values.get(":state"))
            case.pop("callback_owner", None)
            if ":sent" in values:
                case.update(callback_sent_at=values[":at"])
                case.pop("task_token", None)
            else:
                case["callback_error_code"] = values[":code"]
        else:
            raise AssertionError("Unexpected SDK update expression")
        self.history.append(copy.deepcopy(case))
        if self.on_update:
            self.on_update(case)
        return {}

    def query(self, **kwargs):
        self.calls.append(("query", kwargs))
        publication = "publication_state" in kwargs["KeyConditionExpression"]
        state, retry = ("publication_state", "publication_retry_at") if publication else ("notification_state", "notification_retry_at")
        rows = [{"case_id": key} for key, value in self.items.items()
                if value.get(state) == "PENDING" and value.get(retry, 0) <= kwargs["ExpressionAttributeValues"][":now"]]
        return {"Items": rows[:kwargs["Limit"]]}


class FakeS3:
    def __init__(self):
        self.calls = []
        self.fail = False

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise ClientError("AccessDenied")
        return {"ETag": "test-etag"}


class FakeEvents:
    def __init__(self):
        self.calls = []
        self.fail = False

    def put_events(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        return {"FailedEntryCount": 1, "Entries": [{"ErrorCode": "InternalFailure"}]} if self.fail else {"FailedEntryCount": 0, "Entries": [{"EventId": "aws-event-id"}]}
