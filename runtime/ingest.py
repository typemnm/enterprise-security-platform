"""Bounded provider-log ingestion; only registered resources create response cases."""
import base64
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import time
from decimal import Decimal
from .log_provenance import verify_stored_logs

MAX_BYTES = 4 * 1024 * 1024
SOURCE_VALIDATION = "STORED_CLOUDWATCH_V1"


def inflate(data):
    if len(data) > MAX_BYTES:
        raise ValueError("LOG_PAYLOAD_TOO_LARGE")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("LOG_DECOMPRESSED_SIZE_LIMIT")
    return raw


def registered(registry, web_acl_arn, account):
    response = registry.query(IndexName="WebAclArnIndex", KeyConditionExpression="web_acl_arn = :acl",
                              ExpressionAttributeValues={":acl": web_acl_arn}, ProjectionExpression="service_id", Limit=25)
    values = []
    for key in response.get("Items", []):
        value = registry.get_item(Key={"service_id": key["service_id"]}, ConsistentRead=True).get("Item", {})
        if value.get("enabled") is True and value.get("account_id") == account and value.get("web_acl_arn") == web_acl_arn:
            values.append(value)
    return values


def matching_rules(record):
    values = []
    if record.get("action") == "BLOCK" and record.get("terminatingRuleId") != "Default_Action":
        values.append(record.get("terminatingRuleId"))
    for group in record.get("ruleGroupList", []):
        rule = group.get("terminatingRule")
        if isinstance(rule, dict): values.append(rule.get("ruleId"))
        values += [row.get("ruleId") for row in group.get("nonTerminatingMatchingRules", []) if isinstance(row, dict)]
    values += [row.get("ruleId") for row in record.get("nonTerminatingMatchingRules", []) if isinstance(row, dict)]
    return sorted({str(value)[:128] for value in values if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_:.-]{1,128}", value)})


def source_matches(service, record):
    source = record.get("httpSourceId")
    expected_name = {"CLOUDFRONT": "CF", "ALB": "ALB"}.get(service.get("resource_type"))
    if expected_name is None or record.get("httpSourceName") != expected_name:
        return False
    if record.get("cfDistributionTenantId"):
        return False  # Tenant service ownership needs a separately reviewed adapter.
    for arn in service.get("resource_arns", []):
        if service.get("resource_type") == "CLOUDFRONT" and source == arn.rsplit("/", 1)[-1]:
            return True
        if service.get("resource_type") == "ALB" and source in {arn.rsplit("/", 1)[-1], arn, arn.split("loadbalancer/", 1)[-1]}:
            return True
    return False


def waf_signal(record, service):
    rules = matching_rules(record)
    if not rules or not source_matches(service, record): return None
    request = record.get("httpRequest", {})
    address = str(ipaddress.ip_address(request.get("clientIp")))
    millis = record.get("timestamp")
    if type(millis) is not int or not 0 < millis < 2 ** 53:
        raise ValueError("WAF_TIMESTAMP_INVALID")
    observed = dt.datetime.fromtimestamp(millis / 1000, dt.timezone.utc).isoformat().replace("+00:00", "Z")
    event_id = hashlib.sha256(json.dumps([service["service_id"], request.get("requestId"), millis, address, rules], separators=(",", ":")).encode()).hexdigest()
    # No headers, query strings, bodies, access keys or model-generated claims.
    summary = "AWS WAF 규칙 일치 관측. 요청 차단/COUNT 기록은 데이터 유출이나 침투 성공의 증거가 아닙니다."
    if service.get("validation_fixture") is True:
        summary = "[SYNTHETIC PLATFORM VALIDATION] " + service["service_id"] + ": 실제 탐지 및 실제 요청이 아닌 플랫폼 검증용 관측. " + summary
    return {"schema_version": "1.0", "service_id": service["service_id"], "event_id": event_id,
            "signal_type": "WAF_PATTERN", "observed_at": observed, "target": {"source_ip": address},
            "source_resource_arn": service["resource_arns"][0], "confidence": "provider_signal",
            "summary": summary,
            "suggested_action": "monitor", "provider_rule_ids": rules,
            "provider_action": record.get("action") if record.get("action") in ("ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE", "EXCLUDED_AS_COUNT") else "UNKNOWN"}


def integer(value):
    return (type(value) is int or isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value())


def policy_counter(signal, service, now, *, require_fresh=True):
    counters = policy_counters(signal, service, now, require_fresh=require_fresh)
    return counters[0] if counters else None


def policy_counters(signal, service, now, *, require_fresh=True):
    policy = service.get("auto_block_policy", {})
    if not isinstance(policy, dict) or policy.get("enabled") is not True or service.get("response_mode") != "enforce": return []
    seconds, threshold = policy.get("window_seconds"), policy.get("min_requests")
    if (not integer(seconds) or not 60 <= seconds <= 3600 or not integer(threshold) or not 2 <= threshold <= 10000
            or "WAF_PATTERN" not in policy.get("signal_types", []) or not service.get("revision")):
        return []
    observed = int(dt.datetime.fromisoformat(signal["observed_at"].replace("Z", "+00:00")).timestamp())
    if require_fresh and not 0 <= int(now) - observed <= seconds: return []
    rules = sorted(set(signal["provider_rule_ids"]) & set(policy.get("rule_ids", [])))
    if not rules: return []
    # Counts are unique provider events, scoped to exact service, client IP,
    # explicit policy revision, rule and event-time tumbling window.
    counters = []
    for rule in rules:
        identity = json.dumps([service["service_id"], signal["target"]["source_ip"], service["revision"], rule, observed // int(seconds)])
        counters.append({"key": "threshold#" + hashlib.sha256(identity.encode()).hexdigest(), "rule_id": rule,
            "window_seconds": int(seconds), "threshold": int(threshold), "policy_revision": str(service["revision"]),
            "window_start": observed // int(seconds) * int(seconds)})
    return counters


def aggregate_event_id(counter):
    """One immutable case identity per service/IP/rule/revision/event-time window."""
    return hashlib.sha256(("waf-policy-aggregate-v1:" + counter["key"]).encode()).hexdigest()


def observation_key(counter, signal):
    return "observation#" + counter["key"].split("#", 1)[1] + "#" + signal["event_id"]


def counter_fresh(signal, counter, now):
    observed = int(dt.datetime.fromisoformat(signal["observed_at"].replace("Z", "+00:00")).timestamp())
    return 0 <= int(now) - observed <= counter["window_seconds"]


def observation_stamp(signal):
    return dt.datetime.fromisoformat(signal["observed_at"].replace("Z", "+00:00")).astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def confirm_latest(group, row, *, leases, now):
    confirmed = [signal for signal in group["signals"] if counter_fresh(signal, group["counter"], now)]
    if not confirmed: return
    latest = max(observation_stamp(signal) for signal in confirmed)
    address = group["signals"][0]["target"]["source_ip"]
    if row.get("source_ip") not in {None, address}: raise ValueError("OBSERVATION_COUNTER_SCOPE_MISMATCH")
    if row.get("verified_latest_observation", "") >= latest and row.get("source_ip") == address: return
    try:
        leases.update_item(Key={"lease_id": group["counter"]["key"]},
            UpdateExpression="SET source_ip = if_not_exists(source_ip, :ip), verified_latest_observation = :latest",
            ConditionExpression="service_id = :service AND policy_revision = :revision AND (attribute_not_exists(source_ip) OR source_ip = :ip) AND (attribute_not_exists(verified_latest_observation) OR verified_latest_observation < :latest)",
            ExpressionAttributeValues={":ip": address, ":latest": latest, ":service": group["service"]["service_id"], ":revision": group["counter"]["policy_revision"]})
    except Exception:
        observed = leases.get_item(Key={"lease_id": group["counter"]["key"]}, ConsistentRead=True).get("Item", {})
        if observed.get("source_ip") != address or observed.get("verified_latest_observation", "") < latest:
            raise RuntimeError("OBSERVATION_LATEST_NOT_VERIFIED") from None


def encoded_attributes(value):
    from boto3.dynamodb.types import TypeSerializer
    serializer = TypeSerializer()
    return {key: serializer.serialize(item) for key, item in value.items()}


def canonical_signal(signal):
    def numbers(value):
        if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value(): return int(value)
        raise TypeError("SIGNAL_NUMBER_MUST_BE_EXACT_INTEGER")
    return json.dumps(signal, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=numbers)


def observe(signals, service, counter, *, leases, ddb, now):
    group = {"signals": signals, "service": service, "counter": counter}
    return observe_groups({counter["key"]: group}, leases=leases, ddb=ddb, now=now).get(counter["key"], 0)


def observe_groups(groups, *, leases, ddb, now, on_confirmed=None, on_legacy=None, settled=None):
    """Atomic unique observations, independent of case creation or its budget.

    Each transaction has at most 100 items: conditional observation claims and
    one increment per distinct counter. It also packs across many client IPs.
    Each bounded chunk is read, claimed and strongly counted before advancing.
    Its callback may publish a threshold case immediately; a later chunk can
    fail without losing already published cases or committed observations.
    """
    unique = {}
    for group in groups.values():
        selected = dict(group, by_key={})
        for signal in group["signals"]:
            key = observation_key(group["counter"], signal)
            selected["by_key"][key] = signal
            unique[key] = selected
    ordered, cursor, observed_counts, legacy, metadata = sorted(unique), 0, {}, {}, {}
    while cursor < len(ordered):
        pack, counters, deltas = [], set(), {}
        while cursor < len(ordered):
            key = ordered[cursor]
            group = unique[key]
            counter_key = group["counter"]["key"]
            if len(pack) + 1 + len(counters | {counter_key}) > 100: break
            cursor += 1
            pack.append(key)
            counters.add(counter_key)
            deltas[counter_key] = deltas.get(counter_key, 0) + 1
            count = observed_counts.get(counter_key, 0)
            # Publish at the first confirmed threshold boundary, including
            # the 99 + 1 boundary for a 100-request policy.
            if count < group["counter"]["threshold"] <= count + deltas[counter_key]: break
        raw_keys = {"signal#" + unique[key]["service"]["service_id"] + "#" + key.rsplit("#", 1)[-1] for key in pack}
        unread = raw_keys - set(legacy)
        if unread:
            phases = existing_signals(ddb, leases.name, unread)
            legacy.update({key: phases.get(key) for key in unread})
        eligible, touched = [], {}
        for key in pack:
            group = unique[key]
            raw_key = "signal#" + group["service"]["service_id"] + "#" + key.rsplit("#", 1)[-1]
            if legacy[raw_key] is not None:
                if legacy[raw_key] == "PENDING" and on_legacy:
                    on_legacy(raw_key, group)
                    legacy[raw_key] = "REPLAYED"
                continue
            eligible.append(key)
            entry = touched.setdefault(group["counter"]["key"], dict(group, signals=[]))
            # Only confirmed observations from this chunk provide its report
            # timestamp; no later, unclaimed batch record refreshes evidence.
            entry["signals"].append(unique[key]["by_key"][key])
        fresh = [key for key in eligible if counter_fresh(unique[key]["by_key"][key], unique[key]["counter"], now)]
        found = existing_signals(ddb, leases.name, fresh)
        pending = [key for key in fresh if key not in found]
        for attempt in range(4):
            if not pending: break
            writes = [{"Put": {"TableName": leases.name,
                "Item": encoded_attributes({"lease_id": key, "phase": "OBSERVED", "service_id": unique[key]["service"]["service_id"],
                    "counter_key": unique[key]["counter"]["key"], "expires_at": int(now) + 172800}),
                "ConditionExpression": "attribute_not_exists(lease_id)"}} for key in pending]
            counts = {}
            for key in pending:
                group = unique[key]
                counts.setdefault(group["counter"]["key"], {"group": group, "count": 0})["count"] += 1
            for counter_key, entry in counts.items():
                service, counter = entry["group"]["service"], entry["group"]["counter"]
                sources = [unique[key]["by_key"][key] for key in pending if unique[key]["counter"]["key"] == counter_key]
                writes.append({"Update": {"TableName": leases.name, "Key": encoded_attributes({"lease_id": counter_key}),
                    "UpdateExpression": "SET expires_at = :ttl, service_id = :service, #p = :phase, rule_id = :rule, policy_revision = :revision, window_start = :start, window_seconds = :window, threshold = :threshold, source_ip = :ip, verified_latest_observation = if_not_exists(verified_latest_observation, :latest), source_validation_version = :validation ADD #c :delta",
                    "ConditionExpression": "attribute_not_exists(lease_id) OR source_validation_version = :validation",
                    "ExpressionAttributeNames": {"#c": "count", "#p": "phase"},
                    "ExpressionAttributeValues": encoded_attributes({":ttl": int(now) + 172800, ":service": service["service_id"],
                        ":phase": "OBSERVATION_COUNT", ":rule": counter["rule_id"], ":revision": counter["policy_revision"],
                        ":start": counter["window_start"], ":window": counter["window_seconds"], ":threshold": counter["threshold"], ":delta": entry["count"],
                        ":ip": sources[0]["target"]["source_ip"], ":latest": max(observation_stamp(signal) for signal in sources), ":validation": SOURCE_VALIDATION})}})
            try:
                ddb.transact_write_items(TransactItems=writes)
                pending = []
            except Exception as error:
                # Strong reads distinguish an overlapping writer or committed
                # timeout from a transaction that must still be retried.
                committed = existing_signals(ddb, leases.name, pending)
                pending = [key for key in pending if key not in committed]
                if not pending: break
                reasons = getattr(error, "response", {}).get("CancellationReasons", [])
                for index, write in enumerate(writes):
                    if "Update" in write and index < len(reasons) and reasons[index].get("Code") == "ConditionalCheckFailed":
                        from boto3.dynamodb.types import TypeDeserializer
                        key = TypeDeserializer().deserialize(write["Update"]["Key"]["lease_id"])
                        old = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item", {})
                        if old and old.get("source_validation_version") != SOURCE_VALIDATION:
                            raise ValueError("LEGACY_OBSERVATION_COUNTER_REVIEW_REQUIRED") from None
                code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
                if code not in {"TransactionCanceledException", "TransactionConflictException", "ProvisionedThroughputExceededException",
                                "ThrottlingException", "RequestLimitExceeded", "InternalServerError", "RequestTimeout"} and not isinstance(error, (TimeoutError, ConnectionError)) and type(error).__name__ not in {"ReadTimeoutError", "ConnectTimeoutError", "EndpointConnectionError", "ConnectionClosedError"}:
                    raise
                if attempt == 3:
                    raise RuntimeError("OBSERVATION_CLAIM_RETRY_EXHAUSTED") from None
                time.sleep(min(0.025 * 2 ** attempt, 0.1))
        rows = journal_rows(ddb, leases.name, [key for key in touched if not settled or key not in settled], fields=("lease_id", "count", "source_ip", "verified_latest_observation", "source_validation_version"))
        if any(row.get("source_validation_version") != SOURCE_VALIDATION for row in rows.values()):
            raise ValueError("LEGACY_OBSERVATION_COUNTER_REVIEW_REQUIRED")
        metadata.update(rows)
        for key in touched:
            row = metadata.get(key)
            if row:
                confirm_latest(touched[key], row, leases=leases, now=now)
                confirmed = [signal for signal in touched[key]["signals"] if counter_fresh(signal, touched[key]["counter"], now)]
                if confirmed:
                    row["verified_latest_observation"] = max(row.get("verified_latest_observation", ""), max(observation_stamp(signal) for signal in confirmed))
                    row["source_ip"] = confirmed[0]["target"]["source_ip"]
        counts = {key: row.get("count", 0) for key, row in rows.items()}
        observed_counts.update(counts)
        if on_confirmed: on_confirmed(counts, touched)
    return observed_counts


def reserve(signal, service, *, leases, ddb, max_cases, now):
    key = "signal#" + signal["service_id"] + "#" + signal["event_id"]
    prior = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item")
    if prior: return prior
    item = {"lease_id": key, "phase": "PENDING", "expires_at": int(now) + 172800,
            "signal": signal, "publication": canonical_signal(signal), "service_id": service["service_id"]}
    writes = [{"Put": {"TableName": leases.name, "Item": encoded_attributes(item), "ConditionExpression": "attribute_not_exists(lease_id)"}},
        {"Update": {"TableName": leases.name, "Key": encoded_attributes({"lease_id": f"case-budget#{service['service_id']}#{int(now) // 3600}"}),
            "UpdateExpression": "SET expires_at = :ttl ADD #c :one", "ConditionExpression": "attribute_not_exists(#c) OR #c < :limit",
            "ExpressionAttributeNames": {"#c": "count"}, "ExpressionAttributeValues": encoded_attributes({":ttl": int(now) + 172800, ":one": 1, ":limit": max_cases})}}]
    try:
        ddb.transact_write_items(TransactItems=writes)
    except Exception as error:
        # A timeout may have committed: strong-read the signal before retrying.
        prior = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item")
        if prior: return prior
        reasons = getattr(error, "response", {}).get("CancellationReasons", [])
        if len(reasons) > 1 and reasons[1].get("Code") == "ConditionalCheckFailed": return {"phase": "LIMITED"}
        raise
    return item


def emit_case(signal, service, *, leases, ddb, events, bus, max_cases, now):
    reservation = reserve(signal, service, leases=leases, ddb=ddb, max_cases=max_cases, now=now)
    if reservation["phase"] in {"EMITTED", "LIMITED"}: return reservation["phase"]
    # Publication retries use the already reserved immutable provider event.
    signal = dict(reservation["signal"])
    publication = reservation.get("publication") or canonical_signal(signal)
    if not reservation.get("publication"):
        try:
            leases.update_item(Key={"lease_id": reservation["lease_id"]}, UpdateExpression="SET publication = :p",
                ConditionExpression="attribute_not_exists(publication)", ExpressionAttributeValues={":p": publication})
        except Exception:
            observed = leases.get_item(Key={"lease_id": reservation["lease_id"]}, ConsistentRead=True).get("Item", {})
            if not observed.get("publication"): raise
            publication = observed["publication"]
    result = events.put_events(Entries=[{"Source": "security.service", "DetailType": "ServiceSecuritySignal.v1",
        "Detail": publication, "EventBusName": bus}])
    if result.get("FailedEntryCount", 0): raise RuntimeError("SIGNAL_PUBLICATION_FAILED")
    try:
        leases.update_item(Key={"lease_id": reservation["lease_id"]}, UpdateExpression="SET phase = :done",
                           ExpressionAttributeValues={":done": "EMITTED"})
    except Exception:
        if leases.get_item(Key={"lease_id": reservation["lease_id"]}, ConsistentRead=True).get("Item", {}).get("phase") != "EMITTED": raise
    return "EMITTED_NOW"


_UNREAD = object()


def emit_observations(signals, service, counter, *, leases, ddb, events, bus, max_cases, now, count=None, prior=_UNREAD):
    fresh = [signal for signal in signals if counter_fresh(signal, counter, now)]
    if count is None:
        count = observe(fresh, service, counter, leases=leases, ddb=ddb, now=now) if fresh else 0
    event_id = aggregate_event_id(counter)
    key = "signal#" + service["service_id"] + "#" + event_id
    # Existing reservations retain immutable evidence and may replay even when
    # the original provider timestamp has aged out. No new proof is refreshed.
    if prior is _UNREAD:
        prior = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item")
    if prior:
        if prior.get("phase") == "EMITTED": return "EMITTED"
        original = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item", {})
        return emit_case(original["signal"], service, leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)
    if count < counter["threshold"] or not fresh: return "OBSERVED"
    signal = dict(max(fresh, key=lambda item: item["observed_at"]))
    signal["event_id"] = event_id
    signal["policy_evidence"] = {name: counter[name] for name in ("rule_id", "window_seconds", "threshold", "policy_revision")}
    signal["policy_evidence"]["matched_requests"] = int(count)
    signal["suggested_action"] = "block_ip"
    return emit_case(signal, service, leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)


def emit(signal, service, *, leases, ddb, events, bus, max_cases, now):
    previous = leases.get_item(Key={"lease_id": "signal#" + signal["service_id"] + "#" + signal["event_id"]}, ConsistentRead=True).get("Item")
    if previous:
        return emit_case(previous["signal"], service, leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)
    counter = policy_counter(signal, service, now, require_fresh=False)
    method = emit_observations if counter else emit_case
    args = ([signal], service, counter) if counter else (signal, service)
    return method(*args, leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)


def journal_rows(ddb, table_name, keys, *, fields=("lease_id", "phase")):
    from boto3.dynamodb.types import TypeDeserializer
    decoder, result = TypeDeserializer(), {}
    keys = sorted(set(keys))
    for offset in range(0, len(keys), 100):
        aliases = {"#f" + str(index): field for index, field in enumerate(fields)}
        pending = {table_name: {"Keys": [{"lease_id": {"S": key}} for key in keys[offset:offset + 100]],
                               "ConsistentRead": True, "ProjectionExpression": ",".join(aliases), "ExpressionAttributeNames": aliases}}
        for attempt in range(4):
            response = ddb.batch_get_item(RequestItems=pending)
            for item in response.get("Responses", {}).get(table_name, []):
                values = {key: decoder.deserialize(value) for key, value in item.items()}
                result[values["lease_id"]] = values
            pending = response.get("UnprocessedKeys", {})
            if not pending: break
            time.sleep(min(0.1 * 2 ** attempt, 0.5))
        if pending: raise RuntimeError("SIGNAL_JOURNAL_LOOKUP_INCOMPLETE")
    return result


def existing_signals(ddb, table_name, keys):
    return {key: row.get("phase") for key, row in journal_rows(ddb, table_name, keys).items()}


def accept_waf(payload, *, registry, leases, ddb, events, account, bus, source_region, logs=None, max_cases=30, clock=time.time):
    if payload.get("owner") != account:
        raise ValueError("LOG_ACCOUNT_MISMATCH")
    # Subscription permission also binds the AWS account and log namespace.
    group = payload.get("logGroup", "")
    if not isinstance(group, str) or not group.startswith("aws-waf-logs-"):
        raise ValueError("UNEXPECTED_LOG_GROUP")
    if payload.get("messageType") == "CONTROL_MESSAGE": return {"accepted": 0}
    messages = payload.get("logEvents", [])
    if not isinstance(messages, list) or len(messages) > 10000:
        raise ValueError("LOG_BATCH_LIMIT")
    accepted, limited, cache, work, pointers = 0, 0, {}, [], []
    for row in messages:
        if not isinstance(row, dict) or not isinstance(row.get("message"), str): continue
        record = json.loads(row["message"])
        if not isinstance(record, dict) or not matching_rules(record): continue
        acl = record.get("webaclId")
        if not isinstance(acl, str) or len(acl.split(":", 5)) != 6 or acl.split(":", 5)[4] != account:
            raise ValueError("WAF_LOG_RESOURCE_MISMATCH")
        if acl not in cache: cache[acl] = registered(registry, acl, account)
        for service in cache[acl]:
            if service.get("log_group_name") != group or service.get("log_region") != source_region:
                continue
            signal = waf_signal(record, service)
            if signal is None: continue
            work.append((signal, service))
            pointers.append(row)
    # InvokeFunction identity permissions can bypass the Logs resource policy.
    # Only content independently confirmed in the registered stored stream may
    # be counted or emitted; incoming awslogs envelopes are not authority.
    if pointers: verify_stored_logs(payload, pointers, logs)
    now, automatic, manual = int(clock()), {}, []
    for signal, service in work:
        counters = policy_counters(signal, service, now, require_fresh=False)
        if counters:
            for counter in counters:
                group = automatic.setdefault(counter["key"], {"signals": [], "service": service, "counter": counter})
                group["signals"].append(signal)
        else: manual.append((signal, service))
    aggregate_limited, completed = set(), set()

    def replay_legacy(key, group):
        nonlocal accepted
        original = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item", {})
        result = emit_case(original["signal"], group["service"], leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)
        if result == "EMITTED_NOW": accepted += 1

    def publish_confirmed(counts, touched):
        nonlocal accepted, limited
        for counter_key, count in counts.items():
            group = touched[counter_key]
            if counter_key in completed or count < group["counter"]["threshold"]: continue
            service_id = group["service"]["service_id"]
            key = "signal#" + service_id + "#" + aggregate_event_id(group["counter"])
            prior = leases.get_item(Key={"lease_id": key}, ConsistentRead=True).get("Item")
            if service_id in aggregate_limited and not prior:
                limited += 1
                completed.add(counter_key)
                continue
            result = emit_observations(group["signals"], group["service"], group["counter"], leases=leases,
                ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now, count=count, prior=prior)
            if result in {"EMITTED", "EMITTED_NOW", "LIMITED"}: completed.add(counter_key)
            if result == "LIMITED": limited += 1; aggregate_limited.add(service_id)
            if result == "EMITTED_NOW": accepted += 1

    # No whole-fanout lookup/transaction barrier precedes a case. Every
    # confirmed bounded chunk may immediately publish its threshold crossing.
    observe_groups(automatic, leases=leases, ddb=ddb, now=now, on_confirmed=publish_confirmed, on_legacy=replay_legacy, settled=completed)
    exhausted = {}
    for signal, service in manual:
        scope = service["service_id"]
        journal_key = "signal#" + signal["service_id"] + "#" + signal["event_id"]
        if scope in exhausted:
            phase = exhausted[scope].get(journal_key)
            if phase == "EMITTED": continue
            if phase != "PENDING": limited += 1; continue
        result = emit_case(signal, service, leases=leases, ddb=ddb, events=events, bus=bus, max_cases=max_cases, now=now)
        if result == "LIMITED": limited += 1
        if result == "EMITTED_NOW": accepted += 1
        if result == "LIMITED" and scope not in exhausted:
            # During a burst, stop expensive per-event transactions after
            # the hourly cap. Batch reads retain already reserved retries.
            keys = ["signal#" + row["service_id"] + "#" + row["event_id"] for row, svc in manual if svc["service_id"] == scope]
            exhausted[scope] = existing_signals(ddb, leases.name, keys)
    return {"accepted": accepted, "budget_limited": limited}


def handler(event, context):
    import boto3
    from botocore.config import Config
    cfg = Config(connect_timeout=2, read_timeout=5, retries={"mode": "standard", "total_max_attempts": 2})
    region = os.environ["CONTROL_PLANE_REGION"]
    resource = boto3.resource("dynamodb", region_name=region, config=cfg)
    registry = resource.Table(os.environ["REGISTRY_TABLE"])
    leases = resource.Table(os.environ["LEASE_TABLE"])
    account = os.environ["EXPECTED_ACCOUNT"]
    if isinstance(event, dict) and isinstance(event.get("awslogs"), dict):
        raw = inflate(base64.b64decode(event["awslogs"]["data"], validate=True))
        payload = json.loads(raw)
        result = accept_waf(payload, registry=registry, leases=leases,
                            ddb=boto3.client("dynamodb", region_name=region, config=cfg),
                            events=boto3.client("events", region_name=region, config=cfg), account=account,
                            logs=boto3.client("logs", region_name=os.environ["AWS_REGION"], config=cfg),
                            source_region=os.environ["AWS_REGION"],
                            bus=os.environ["EVENT_BUS_ARN"], max_cases=int(os.environ.get("MAX_CASES_PER_HOUR", "30")))
    else:
        raise ValueError("UNSUPPORTED_LOG_INGRESS")
    if result.get("budget_limited", 0):
        boto3.client("cloudwatch", region_name=region, config=cfg).put_metric_data(
            Namespace="EnterpriseSecurity/Operations", MetricData=[{"MetricName": "CaseBudgetLimited", "Unit": "Count",
                "Value": result["budget_limited"], "Dimensions": [{"Name": "InstallationId", "Value": os.environ["INSTALLATION_ID"]},
                    {"Name": "Environment", "Value": os.environ["ENVIRONMENT"]}]}])
    print(json.dumps({"event": "SERVICE_LOG_INGRESS", "installation_id": os.environ.get("INSTALLATION_ID", "unconfigured"),
                      "environment": os.environ.get("ENVIRONMENT", "unconfigured"), **result}))
    return result
