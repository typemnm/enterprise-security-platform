"""Corporate Slack delivery contract tests. No AWS or Slack calls are made."""
import copy
from datetime import datetime, timezone
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ENTERPRISE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENTERPRISE))
sys.path.insert(0, str(ENTERPRISE / "runtime"))
from runtime import notifier
import publication_events
import outbox_delivery
import publication

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
SERVICE = "checkout-prod"
CASE = "inv-" + "a" * 32
BUCKET = "company-security-audit"
CHANNEL = "C12345678"
TOKEN = "xoxb-12345678901234567890-secret"
SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:slack-notifications-AbCd12"
TRANSPORT = "12345678-1234-1234-1234-123456789abc"


class Registry:
    def __init__(self, **overrides):
        self.item = {"service_id": SERVICE, "account_id": ACCOUNT, "enabled": True,
                     "audit_bucket": BUCKET, "report_bucket": BUCKET, **overrides}
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        return {"Item": copy.deepcopy(self.item)} if self.item else {}


class FakeStore:
    def __init__(self):
        self.records, self.fail_put, self.fail_receipt = {}, False, False

    def get(self, key):
        return copy.deepcopy(self.records.get(key, {}))

    def claim(self, key, owner, now, lease):
        existing = self.records.get(key, {})
        if existing.get("status") in {"SENT", "UNKNOWN"}:
            return False
        if existing.get("retry_at", 0) > now or existing.get("lease_until", 0) > now:
            return False
        self.records[key] = {**existing, "status": "PENDING", "lease_owner": owner, "lease_until": now + lease}
        return True

    def receipt(self, key, owner, status, *, now, code=None, retry_at=0):
        if self.fail_receipt and status == "SENT":
            raise RuntimeError("injected receipt gap")
        record = self.records[key]
        self.assert_owner(record, owner, "lease_owner")
        record.update(status=status, retry_at=retry_at, last_code=code)
        record.pop("lease_owner", None)
        record.pop("lease_until", None)

    def assert_owner(self, record, owner, field):
        if record.get(field) != owner:
            raise AssertionError("wrong lease owner")

    def begin_send(self, key, owner, method, now):
        self.assert_owner(self.records[key], owner, "lease_owner")
        self.records[key].update(send_started=True, last_method=method)

    def put_message(self, key, value):
        if self.fail_put:
            raise RuntimeError("injected commit gap")
        self.records[key] = copy.deepcopy(value)

    def begin_update(self, key, owner, previous, now, lease):
        record = self.records[key]
        if (record.get("revision") != previous["revision"] or record.get("ts") != previous["ts"]
                or record.get("channel") != previous["channel"]
                or record.get("update_owner") and record.get("update_until", now + 1) >= now):
            raise notifier.NoticeError("MESSAGE_UPDATE_BUSY_OR_CHANGED", retry_after=15)
        record.update(update_owner=owner, update_until=now + lease)

    def commit_update(self, key, owner, value):
        self.assert_owner(self.records[key], owner, "update_owner")
        self.put_message(key, value)

    def release_update(self, key, owner):
        record = self.records[key]
        self.assert_owner(record, owner, "update_owner")
        record.pop("update_owner", None)
        record.pop("update_until", None)

    def begin_first_post(self, key, owner, now, lease):
        record = self.records.setdefault(key, {})
        if record.get("ts") or record.get("delivery_state") not in {None, "RETRY"}:
            raise notifier.NoticeError("FIRST_POST_GATE_BUSY")
        record.update(delivery_state="POSTING", gate_owner=owner, gate_until=now + lease)

    def first_post_gate_state(self, key, owner, state, code):
        record = self.records[key]
        self.assert_owner(record, owner, "gate_owner")
        record.update(delivery_state=state, last_delivery_code=code)
        record.pop("gate_owner", None)
        record.pop("gate_until", None)

    def hold_expired_post(self, key, now):
        self.records[key]["status"] = "UNKNOWN"

    def hold_expired_gate(self, key, now):
        self.records[key]["delivery_state"] = "UNKNOWN"


class FakeS3:
    def __init__(self):
        self.heads = []
        self.metadata = {}

    def head_object(self, **kwargs):
        self.heads.append(kwargs)
        return {"Metadata": copy.deepcopy(self.metadata)}

    def get_object(self, **kwargs):
        raise AssertionError("Notifier must never fetch the report body")


class CaseJournal:
    def __init__(self, s3): self.row, self.calls, self.s3 = {}, [], s3
    def commit(self, event):
        detail = copy.deepcopy(event["detail"])
        phase, kind = detail["publication_type"], detail["report_kind"]
        attr = publication_events.outbox_attribute(phase, kind)
        previous = self.row.get(attr)
        if previous and previous["event_id"] == detail["event_id"]:
            return  # The real producer preserves immutable first publication time.
        outbox = {"status": "EMITTED", "event_id": detail["event_id"], "detail": detail}
        self.row.update(case_id=detail["case_id"], service_id=detail["service_id"], dashboard_bucket=detail["result"]["bucket"],
                        dashboard_key=detail["result"]["key"])
        self.row[attr] = outbox
        if phase == "INITIAL" and self.row.get("dashboard_publication", {}).get("phase") == "OUTCOME": return
        job = publication.make_job(detail["case_id"], detail["service_id"], detail["result"]["bucket"], detail["result"]["key"],
                                   "Private report contents excluded from notifier reads", phase, attr, outbox, 1)
        job["state"] = "PUBLISHED"
        self.row.update(publication_state="PUBLISHED", publication_revision=job["revision"], dashboard_publication=job,
                        task_token="private-never-request", report_md="private-never-request")
        self.s3.metadata = {"publication-revision": job["revision"], "service-id": detail["service_id"]}
    def get_item(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        aliases, result = kwargs["ExpressionAttributeNames"], {}
        for path in kwargs["ProjectionExpression"].split(","):
            names = [aliases[value] for value in path.split(".")]
            if any(value in {"task_token", "report_md", "body"} for value in names):
                raise AssertionError("Private case fields must not be read")
            value = self.row
            for name in names:
                if not isinstance(value, dict) or name not in value: break
                value = value[name]
            else:
                target = result
                for name in names[:-1]: target = target.setdefault(name, {})
                target[names[-1]] = copy.deepcopy(value)
        return {"Item": result}


class FakeSlack:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def call(self, method, payload):
        self.calls.append((method, copy.deepcopy(payload)))
        if self.error:
            raise self.error
        return {"channel": payload["channel"], "ts": "1750000000.123456"}


class FakeSecrets:
    def __init__(self, token=TOKEN):
        self.token, self.calls = token, []

    def get_secret_value(self, **kwargs):
        self.calls.append(kwargs)
        return {"SecretString": json.dumps({"bot_token": self.token}), "ARN": kwargs["SecretId"],
                "ResponseMetadata": {"RequestId": "12345678-1234-1234-1234-123456789abc"}}


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


def published(config, *, state="TRIAGED", phase="INITIAL", service=SERVICE, tier=1,
              summary="공격 IP에서 비정상 접근 시도를 확인했습니다.", time="2026-10-14T01:00:00Z",
              key=None, target=None, response=None, failures=None, recommended="block_ip", decision=None):
    item = publication_events.make_outbox(CASE, service, state, tier, config.dashboard_bucket,
        key or service + "/" + CASE + ".md", time, phase=phase, summary=summary,
        recommended_action=recommended, target=target, response=response, failures=failures, decision=decision)
    return {"account": config.account, "region": config.region, "source": "whs.hitl.dashboard",
            "detail-type": "DashboardReportPublished.v1",
            "detail": outbox_delivery.project(item, expected_case=CASE, expected_service=service)}


class CorporateNotifierTests(unittest.TestCase):
    def setUp(self):
        notifier._TOKEN_CACHE.clear()
        self.cfg = notifier.Config(account=ACCOUNT, region=REGION, channel=CHANNEL,
                                   secret_arn=SECRET, dashboard_bucket=BUCKET)
        self.registry, self.store, self.s3, self.slack = Registry(), FakeStore(), FakeS3(), FakeSlack()
        self.cases = CaseJournal(self.s3)
        self.now = 1800000000

    def normalize(self, event):
        return notifier.normalize(event, self.cfg, self.registry)

    def deliver(self, event, **kwargs):
        if kwargs.get("commit", True): self.cases.commit(event)
        return notifier.deliver(event, config=self.cfg, registry=self.registry, store=self.store,
                                s3=self.s3, slack=kwargs.get("slack", self.slack), cases=self.cases, clock=lambda: self.now)

    def payload_text(self, event):
        payload = notifier.message_payload(self.normalize(event), CHANNEL)
        self.assertFalse(payload["mrkdwn"])
        self.assertEqual(payload["parse"], "none")
        self.assertTrue(all(row["text"]["type"] == "plain_text" for row in payload["blocks"]))
        return "\n".join(row["text"]["text"] for row in payload["blocks"])

    def assert_notice(self, code, function):
        with self.assertRaises(notifier.NoticeError) as caught:
            function()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_actual_producer_project_contract_initial_and_terminal_states(self):
        for state, phase, tier in (("TRIAGED", "INITIAL", 1), ("AWAITING_APPROVAL", "INITIAL", 2),
                                  ("AUTO_BLOCK_PARTIAL", "OUTCOME", 1), ("BLOCK_PARTIAL", "OUTCOME", 2),
                                  ("AI1_FAILED", "OUTCOME", 3), ("TIMED_OUT", "OUTCOME", 2)):
            with self.subTest(state=state):
                event = published(self.cfg, state=state, phase=phase, tier=tier)
                result = self.normalize(event)
                self.assertEqual(result["status"], state)
                self.assertEqual(result["service_id"], SERVICE)
        self.assertTrue(all(row["ConsistentRead"] for row in self.registry.calls))

    def test_registry_account_enable_and_bucket_binding(self):
        for overrides, code in (({"account_id": "999999999999"}, "SERVICE_NOT_REGISTERED"),
                                ({"enabled": False}, "SERVICE_NOT_REGISTERED"),
                                ({"service_id": "another-app"}, "SERVICE_NOT_REGISTERED"),
                                ({"audit_bucket": "another-bucket"}, "SERVICE_REPORT_BUCKET_MISMATCH"),
                                ({"report_bucket": "another-bucket"}, "SERVICE_REPORT_BUCKET_MISMATCH")):
            with self.subTest(overrides=overrides):
                registry = Registry(**overrides)
                self.assert_notice(code, lambda: notifier.normalize(published(self.cfg), self.cfg, registry))
        self.assert_notice("SERVICE_REGISTRY_REQUIRED", lambda: notifier.normalize(published(self.cfg), self.cfg, None))

    def test_event_origin_pointer_kind_and_revision_fail_closed(self):
        for change, code in (({"account": "999999999999"}, "UNTRUSTED_EVENT_ORIGIN"),
                             ({"region": "us-east-1"}, "UNTRUSTED_EVENT_ORIGIN"),
                             ({"source": "whs.ir.reporting"}, "UNTRUSTED_EVENT_TYPE"),
                             ({"detail-type": "IncidentResponseReportReady.v1"}, "UNTRUSTED_EVENT_TYPE")):
            event = published(self.cfg)
            event.update(change)
            self.assert_notice(code, lambda: self.normalize(event))
        for name, value, code in (("service_id", "../../other", "INVALID_SERVICE_ID"),
                                 ("report_kind", "FORENSIC", "INVALID_CASE_OR_KIND"),
                                 ("case_id", "inv-one", "INVALID_CASE_OR_KIND"),
                                 ("event_id", "a" * 63, "INVALID_REVISION"),
                                 ("revision", "b" * 64, "INVALID_REVISION"),
                                 ("result", {"bucket": BUCKET, "key": "other-app/" + CASE + ".md"}, "UNTRUSTED_REPORT_LOCATION")):
            event = published(self.cfg)
            event["detail"][name] = value
            self.assert_notice(code, lambda: self.normalize(event))
        event = published(self.cfg)
        event["detail"]["result"]["bucket"] = "other-bucket"
        self.assert_notice("UNTRUSTED_REPORT_LOCATION", lambda: self.normalize(event))

    def test_all_safe_visible_content_is_revision_bound(self):
        response = {"components": {"waf": {"status": "APPLIED"}}, "response_status": "APPLIED"}
        event = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME", response=response,
                          target={"source_ip": "8.8.8.8"})
        for change in ({"report_summary": "변조된 요약"}, {"recommended_action": "monitor"}, {"tier": 0},
                       {"target": {"source_ip": "1.1.1.1"}}, {"response_status": "FAILED"},
                       {"actual_outcomes": {"waf": {"status": "FAILED"}}},
                       {"failure_codes": {"failure": "UnexpectedError"}}, {"response_error_code": "UnexpectedError"}):
            modified = copy.deepcopy(event)
            modified["detail"].update(change)
            self.assert_notice("PUBLICATION_REVISION_MISMATCH", lambda: self.normalize(modified))
        modified = copy.deepcopy(event)
        modified["detail"]["decided_action"] = "isolate_instance"
        self.assert_notice("PUBLICATION_ACTION_MISMATCH", lambda: self.normalize(modified))

    def test_partial_result_is_described_per_component_not_as_full_success(self):
        event = published(self.cfg, state="AUTO_BLOCK_PARTIAL", phase="OUTCOME",
            target={"source_ip": "2001:4860:4860::8888"}, response={"response_status": "PARTIAL",
            "components": {"waf": {"status": "APPLIED"}, "nacl": {"status": "FAILED", "error_code": "NACL_UPDATE_FAILED"}}})
        text = self.payload_text(event)
        for fragment in ("서비스: " + SERVICE, "일부", "WAF: 적용 완료", "NACL: 실패", "NACL_UPDATE_FAILED", "IP: 2001:4860:4860::8888"):
            self.assertIn(fragment, text)
        self.assertNotIn("실행 결과: 실행 완료", text)

    def test_unknown_evidence_never_claims_actual_block(self):
        text = self.payload_text(published(self.cfg, state="AUTO_BLOCK_UNVERIFIED", phase="OUTCOME",
                                           response={"response_status": "UNVERIFIED"}))
        self.assertIn("결과 확인 필요", text)
        self.assertNotIn("실행 결과: 실행 완료", text)
        failed = self.payload_text(published(self.cfg, state="AI1_FAILED", phase="OUTCOME"))
        self.assertIn("실행하지 않음", failed)

    def test_success_status_without_actual_waf_evidence_remains_unverified(self):
        for response in (None, {"response_status": "APPLIED"},
                         {"response_status": "PARTIAL", "components": {"waf": {"status": "APPLIED"}}}):
            with self.subTest(response=response):
                text = self.payload_text(published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME", response=response))
                self.assertIn("결과 미확인", text)
                self.assertNotIn("자동 IP 차단 완료", text)
                self.assertNotIn("실행 결과: 실행 완료", text)
        text = self.payload_text(published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME",
            response={"response_status": "APPLIED", "components": {"waf": {"status": "ALREADY_PRESENT"}}}))
        self.assertIn("실행 결과: 실행 완료", text)

    def test_summary_is_selected_and_credentials_raw_report_and_token_never_leave(self):
        summary = "<!channel> <@U123> taskToken=private-callback bot_token=" + TOKEN + " https://internal.example/private " + "Q" * 60
        event = published(self.cfg, summary=summary)
        event["detail"].update(task_token="must-not-leave", report_body="private report contents",
                                failure={"Cause": "private failure evidence"}, decision_reason="private reason")
        text = self.payload_text(event)
        for secret in ("private-callback", TOKEN, "internal.example", "Q" * 60, "must-not-leave", "private report", "private reason"):
            self.assertNotIn(secret, text)
        self.assertIn("<!channel>", text)  # harmless Slack plain_text, never mrkdwn

    def test_failure_codes_are_selected_no_cause_or_opaque_secret(self):
        event = published(self.cfg, state="BLOCK_FAILED", phase="OUTCOME", tier=2,
            failures={"block_error": {"Error": "AccessDeniedException", "Cause": TOKEN},
                      "failure": {"Error": TOKEN}, "extra": {"Error": "private-extra"}})
        text = self.payload_text(event)
        self.assertIn("AccessDeniedException", text)
        self.assertIn("UNCLASSIFIED_ERROR", text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("private-extra", text)

    def test_exact_duplicate_timestamp_retry_no_second_post_or_secret_fetch(self):
        event = published(self.cfg)
        secrets = FakeSecrets()
        sender = notifier.CredentialSlack(secrets, self.cfg)
        with patch.object(notifier, "Slack", return_value=self.slack):
            self.assertEqual(self.deliver(event, slack=sender), "POSTED")
            self.assertEqual(self.deliver(event, slack=sender), "DUPLICATE")
            self.assert_notice("CASE_OUTBOX_CONTENT_MISMATCH", lambda: self.deliver(published(self.cfg, time="2026-10-14T02:00:00Z"), slack=sender))
        self.assertEqual(len(secrets.calls), 1)
        self.assertEqual(len(self.slack.calls), 1)
        self.assertEqual(self.s3.heads, [{"Bucket": BUCKET, "Key": SERVICE + "/" + CASE + ".md"}] * 2)

    def test_initial_cannot_rewind_outcome_even_with_later_publication_time(self):
        self.deliver(published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME"))
        self.assertEqual(self.deliver(published(self.cfg, time="2026-10-15T01:00:00Z")), "STALE")
        self.assertEqual(len(self.slack.calls), 1)

    def test_outcome_advances_initial_even_with_older_time_and_updates_same_message(self):
        self.deliver(published(self.cfg, time="2026-10-15T01:00:00Z"))
        self.assertEqual(self.deliver(published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME")), "UPDATED")
        self.assertEqual([method for method, _ in self.slack.calls], ["chat.postMessage", "chat.update"])
        self.assertEqual(self.slack.calls[1][1]["ts"], "1750000000.123456")

    def test_concurrent_revisions_serialize_updates_and_eventually_keep_newest(self):
        self.deliver(published(self.cfg))
        older = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME", time="2026-10-14T02:00:00Z")
        newer = published(self.cfg, state="AUTO_BLOCK_PARTIAL", phase="OUTCOME", time="2026-10-14T03:00:00Z")
        outer = self
        class InterleavingSlack(FakeSlack):
            def call(inner, method, payload):
                outer.assert_notice("MESSAGE_UPDATE_BUSY_OR_CHANGED", lambda: outer.deliver(newer))
                return super().call(method, payload)
        self.assertEqual(self.deliver(older, slack=InterleavingSlack()), "UPDATED")
        self.now += 16
        self.assertEqual(self.deliver(newer), "UPDATED")
        notice = self.normalize(newer)
        self.assertEqual(self.store.records[notice["message_key"]]["revision"], notice["revision"])
        self.assertEqual(self.store.records[notice["message_key"]]["status"], "AUTO_BLOCK_PARTIAL")
        self.assertNotIn("update_owner", self.store.records[notice["message_key"]])

    def test_update_failure_releases_message_lease_and_retries_existing_ts(self):
        self.deliver(published(self.cfg))
        outcome = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME")
        self.slack.error = notifier.NoticeError("SLACK_DELIVERY_UNCERTAIN")
        self.assert_notice("SLACK_DELIVERY_UNCERTAIN", lambda: self.deliver(outcome))
        self.assertNotIn("update_owner", self.store.records[self.normalize(outcome)["message_key"]])
        self.slack.error = None
        self.assertEqual(self.deliver(outcome), "UPDATED")
        self.assertEqual([method for method, _ in self.slack.calls], ["chat.postMessage", "chat.update", "chat.update"])

    def test_same_case_and_revision_different_service_or_channel_do_not_share_receipts(self):
        first = self.normalize(published(self.cfg))
        second = notifier.normalize(published(self.cfg, service="billing-prod"), self.cfg, Registry(service_id="billing-prod"))
        third = notifier.normalize(published(self.cfg), replace(self.cfg, channel="C87654321"), self.registry)
        self.assertEqual(len({notice["message_key"] for notice in (first, second, third)}), 3)
        self.assertEqual(len({notice["event_key"] for notice in (first, second, third)}), 3)

    def test_rate_limit_records_retry_delay_and_retries_without_unknown_hold(self):
        event = published(self.cfg)
        self.slack.error = notifier.NoticeError("SLACK_RATE_LIMITED", retry_after=300)
        self.assert_notice("SLACK_RATE_LIMITED", lambda: self.deliver(event))
        notice = self.normalize(event)
        self.assertEqual(self.store.records[notice["event_key"]]["status"], "RETRY")
        self.assertEqual(self.store.records[notice["message_key"]]["delivery_state"], "RETRY")
        self.slack.error = None
        self.assert_notice("CLAIM_BUSY_OR_RETRY_DELAY", lambda: self.deliver(event))
        self.now += 301
        self.assertEqual(self.deliver(event), "POSTED")

    def test_ambiguous_first_post_is_held_no_blind_retry(self):
        event = published(self.cfg)
        self.slack.error = notifier.NoticeError("SLACK_DELIVERY_UNCERTAIN", ambiguous=True)
        self.assert_notice("SLACK_DELIVERY_UNCERTAIN", lambda: self.deliver(event))
        self.slack.error = None
        self.now += 1000
        self.assert_notice("DELIVERY_UNKNOWN_REQUIRES_REVIEW", lambda: self.deliver(event))
        outcome = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME")
        self.assert_notice("CASE_DELIVERY_UNKNOWN_REQUIRES_REVIEW", lambda: self.deliver(outcome))
        self.assertEqual(len(self.slack.calls), 1)

    def test_success_then_message_commit_failure_is_held(self):
        event = published(self.cfg)
        self.store.fail_put = True
        self.assert_notice("DEPENDENCY_FAILED", lambda: self.deliver(event))
        self.store.fail_put = False
        self.now += 1000
        self.assert_notice("DELIVERY_UNKNOWN_REQUIRES_REVIEW", lambda: self.deliver(event))
        self.assertEqual(len(self.slack.calls), 1)

    def test_success_message_commit_then_receipt_gap_recovers_without_duplicate(self):
        event = published(self.cfg)
        self.store.fail_receipt = True
        self.assert_notice("DEPENDENCY_FAILED", lambda: self.deliver(event))
        self.store.fail_receipt = False
        self.now += 151
        self.assertEqual(self.deliver(event), "DUPLICATE")
        self.assertEqual(len(self.slack.calls), 1)

    def test_expired_post_journal_and_expired_case_gate_are_never_reposted(self):
        event = published(self.cfg)
        notice = self.normalize(event)
        self.store.records[notice["event_key"]] = {"status": "PENDING", "lease_until": self.now - 1,
                                                     "send_started": True, "last_method": "chat.postMessage"}
        self.assert_notice("DELIVERY_UNKNOWN_REQUIRES_REVIEW", lambda: self.deliver(event))
        self.store.records.clear()
        self.store.records[notice["message_key"]] = {"delivery_state": "POSTING", "gate_until": self.now - 1}
        self.assert_notice("CASE_DELIVERY_UNKNOWN_REQUIRES_REVIEW", lambda: self.deliver(event))
        self.assertEqual(len(self.slack.calls), 0)

    def test_invalid_disabled_duplicate_and_pre_activation_never_fetch_secret(self):
        secrets = FakeSecrets()
        sender = notifier.CredentialSlack(secrets, self.cfg)
        invalid = published(self.cfg)
        invalid["account"] = "999999999999"
        self.assert_notice("UNTRUSTED_EVENT_ORIGIN", lambda: self.deliver(invalid, slack=sender))
        self.cfg = replace(self.cfg, notify_after_utc="2026-10-15T01:00:00Z")
        self.assertEqual(self.deliver(published(self.cfg), slack=sender), "BEFORE_ACTIVATION_SKIPPED")
        with patch.dict(os.environ, {"NOTIFICATIONS_ENABLED": "false"}, clear=True), patch.dict(sys.modules, {"boto3": None}):
            self.assertEqual(notifier.handler({}, object())["notifications"], "DISABLED")
        self.assertEqual(secrets.calls, [])

    def test_secret_fetch_failure_is_retryable_before_side_effect_journal(self):
        secrets = FakeSecrets(token="bad-token")
        sender = notifier.CredentialSlack(secrets, self.cfg)
        event = published(self.cfg)
        self.assert_notice("INVALID_BOT_TOKEN", lambda: self.deliver(event, slack=sender))
        record = self.store.records[self.normalize(event)["event_key"]]
        self.assertEqual(record["status"], "RETRY")
        self.assertNotIn("send_started", record)

    def test_secret_cache_is_bound_to_secret_identity_and_expires(self):
        first, second = FakeSecrets(), FakeSecrets(token="xoxb-second-12345678901234567890")
        self.assertEqual(notifier.get_token(first, self.cfg, clock=lambda: 100), TOKEN)
        self.assertEqual(notifier.get_token(first, self.cfg, clock=lambda: 200), TOKEN)
        different = replace(self.cfg, secret_arn=SECRET.replace("AbCd12", "EfGh34"))
        self.assertEqual(notifier.get_token(second, different, clock=lambda: 200), second.token)
        self.assertEqual(len(first.calls), 1)
        notifier.get_token(first, self.cfg, clock=lambda: 401)
        self.assertEqual(len(first.calls), 2)
        untrusted = replace(self.cfg, secret_arn=SECRET.replace(ACCOUNT, "999999999999"))
        self.assert_notice("UNTRUSTED_SLACK_SECRET", lambda: notifier.get_token(first, untrusted))

    def test_flat_legacy_key_requires_explicit_matching_profile(self):
        event = published(self.cfg, service="legacy-whs", key=CASE + ".md")
        registry = Registry(service_id="legacy-whs")
        self.assert_notice("UNTRUSTED_REPORT_LOCATION", lambda: notifier.normalize(event, self.cfg, registry))
        cfg = replace(self.cfg, default_service_id="legacy-whs")
        self.assertEqual(notifier.normalize(event, cfg, registry)["key"], CASE + ".md")

    def test_http_rejection_rate_limit_timeout_and_recipient_mismatch(self):
        payload = {"channel": CHANNEL, "text": "test"}
        def rate_limit(request, timeout):
            raise HTTPError(request.full_url, 429, "rate limit", {"Retry-After": "321"}, io.BytesIO(b"private-body"))
        error = self.assert_notice("SLACK_RATE_LIMITED", lambda: notifier.Slack(TOKEN, rate_limit).call("chat.postMessage", payload))
        self.assertEqual(error.retry_after, 321)
        def timeout(request, timeout):
            raise URLError("private host details")
        error = self.assert_notice("SLACK_DELIVERY_UNCERTAIN", lambda: notifier.Slack(TOKEN, timeout).call("chat.postMessage", payload))
        self.assertTrue(error.ambiguous)
        other = lambda *a, **k: FakeResponse(json.dumps({"ok": True, "channel": "C87654321", "ts": "1750000000.123456"}).encode())
        error = self.assert_notice("SLACK_DELIVERY_UNCERTAIN", lambda: notifier.Slack(TOKEN, other).call("chat.postMessage", payload))
        self.assertTrue(error.ambiguous)
        denial = lambda *a, **k: FakeResponse(b'{"ok": false, "error": "channel_not_found"}')
        error = self.assert_notice("SLACK_API_channel_not_found", lambda: notifier.Slack(TOKEN, denial).call("chat.postMessage", payload))
        self.assertFalse(error.ambiguous)

    def test_partial_batch_failure_visibility_delay_and_no_secret_error_logging(self):
        records = [{"messageId": TRANSPORT, "body": "{}", "receiptHandle": "transport-receipt"}]
        delayed = []
        def failing(body):
            raise notifier.NoticeError("SLACK_RATE_LIMITED", retry_after=400)
        with self.assertLogs(notifier.LOG, level="WARNING") as logs:
            result = notifier.handle_batch({"Records": records}, dispatch=failing,
                delay_retry=lambda row, seconds: delayed.append((row["receiptHandle"], seconds)))
        self.assertEqual(result, {"batchItemFailures": [{"itemIdentifier": TRANSPORT}]})
        self.assertEqual(delayed, [("transport-receipt", 400)])
        def secret_failure(body):
            raise RuntimeError(TOKEN + " task_token=do-not-log")
        with self.assertLogs(notifier.LOG, level="WARNING") as logs:
            notifier.handle_batch({"Records": records}, dispatch=secret_failure)
        self.assertNotIn(TOKEN, " ".join(logs.output))
        self.assertNotIn("do-not-log", " ".join(logs.output))

    def test_handler_wraps_secrets_with_invocation_context_and_registry_binding(self):
        event = published(self.cfg)
        secrets, sent, wrapped = FakeSecrets(), FakeSlack(), []
        context = types.SimpleNamespace(invoked_function_arn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:security-notifier",
                                        aws_request_id=TRANSPORT)
        class Resource:
            def Table(inner, name):
                return self.registry if name == "registry" else self.cases if name == "cases" else object()
        clients = {"s3": self.s3, "secretsmanager": secrets, "sqs": object()}
        sdk = types.SimpleNamespace(resource=lambda name: Resource(), client=lambda name: clients[name])
        environment = {"NOTIFICATIONS_ENABLED": "true", "EXPECTED_ACCOUNT": ACCOUNT, "AWS_REGION": REGION,
                       "SLACK_CHANNEL_ID": CHANNEL, "SLACK_SECRET_ARN": SECRET, "AUDIT_BUCKET": BUCKET,
                       "NOTIFICATIONS_TABLE": "receipts", "REGISTRY_TABLE": "registry", "CASES_TABLE": "cases", "QUEUE_URL": "https://sqs.test/queue"}
        self.cases.commit(event)
        def attested(client, ctx):
            wrapped.append((client, ctx))
            return client
        with patch.dict(os.environ, environment, clear=True), patch.dict(sys.modules, {"boto3": sdk}), \
             patch.object(notifier, "Store", return_value=self.store), patch.object(notifier, "wrap", side_effect=attested), \
             patch.object(notifier, "Slack", return_value=sent):
            result = notifier.handler({"Records": [{"messageId": TRANSPORT, "body": json.dumps(event)}]}, context)
        self.assertEqual(result["batchItemFailures"], [])
        self.assertEqual(wrapped, [(secrets, context)])
        self.assertEqual(len(secrets.calls), 1)
        self.assertEqual(len(sent.calls), 1)

    def test_rehashed_forged_status_components_or_summary_never_post_or_claim(self):
        original = published(self.cfg, state="AUTO_BLOCK_FAILED", phase="OUTCOME", response={"response_status": "FAILED",
                             "components": {"waf": {"status": "FAILED"}}})
        self.cases.commit(original)
        forged = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME", response={"response_status": "APPLIED",
                           "components": {"waf": {"status": "APPLIED"}}})
        secrets = FakeSecrets(); sender = notifier.CredentialSlack(secrets, self.cfg)
        self.assert_notice("CASE_OUTBOX_CONTENT_MISMATCH", lambda: self.deliver(forged, commit=False, slack=sender))
        self.assertEqual(self.slack.calls, []); self.assertEqual(secrets.calls, []); self.assertEqual(self.store.records, {})
        self.assertEqual(self.s3.heads, [])
        self.assertTrue(self.cases.calls[0]["ConsistentRead"])

    def test_timestamp_cannot_be_forged_even_with_same_revision_or_authoritative_future(self):
        event = published(self.cfg); self.cases.commit(event)
        changed = copy.deepcopy(event); changed["detail"]["published_at"] = "2026-10-14T02:00:00Z"
        self.assert_notice("CASE_OUTBOX_CONTENT_MISMATCH", lambda: self.deliver(changed, commit=False))
        future = datetime.fromtimestamp(self.now + 60, timezone.utc).isoformat().replace("+00:00", "Z")
        self.assert_notice("PUBLICATION_TIME_IN_FUTURE", lambda: self.deliver(published(self.cfg, time=future)))
        self.assertEqual(self.slack.calls, []); self.assertEqual(self.store.records, {})

    def test_missing_private_version_or_pending_publication_never_claim_or_send(self):
        event = published(self.cfg); self.cases.commit(event)
        self.s3.metadata = {}
        error = self.assert_notice("PUBLICATION_OBJECT_VERSION_NOT_COMMITTED", lambda: self.deliver(event, commit=False))
        self.assertEqual(error.retry_after, 60)
        self.cases.row["publication_state"] = "PENDING"
        self.cases.row["dashboard_publication"]["state"] = "PENDING"
        error = self.assert_notice("PUBLICATION_NOT_COMMITTED", lambda: self.deliver(event, commit=False))
        self.assertEqual(error.retry_after, 60)
        self.assertEqual(self.slack.calls, []); self.assertEqual(self.store.records, {})

    def test_initial_journal_is_safe_dropped_after_outcome_without_receipt(self):
        initial = published(self.cfg); self.cases.commit(initial)
        outcome = published(self.cfg, state="AUTO_BLOCKED", phase="OUTCOME", response={"response_status": "APPLIED",
                            "components": {"waf": {"status": "APPLIED"}}})
        self.cases.commit(outcome)
        self.assertEqual(self.deliver(initial, commit=False), "STALE")
        self.assertEqual(self.store.records, {}); self.assertEqual(self.s3.heads, []); self.assertEqual(self.slack.calls, [])
        self.assertEqual(self.deliver(outcome, commit=False), "POSTED")

    def test_no_case_authority_or_private_hash_mismatch_fails_closed(self):
        event = published(self.cfg)
        self.assert_notice("CASE_PUBLICATION_JOURNAL_REQUIRED", lambda: notifier.deliver(event, config=self.cfg, registry=self.registry,
            store=self.store, s3=self.s3, slack=self.slack, clock=lambda: self.now))
        self.cases.commit(event)
        self.cases.row["dashboard_publication"]["body_sha256"] = "a" * 64
        self.assert_notice("PRIVATE_PUBLICATION_IDENTITY_MISMATCH", lambda: self.deliver(event, commit=False))
        self.assertEqual(self.slack.calls, []); self.assertEqual(self.store.records, {})


if __name__ == "__main__":
    unittest.main()
