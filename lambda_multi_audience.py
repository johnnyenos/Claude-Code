"""
AWS Security Hub Multi-Audience Reporter – Lambda Function
Python 3.12 + boto3

PURPOSE
-------
Drop-in replacement for lambda_function.py that publishes to TWO SNS topics:

  • Technical topic  (SNS_TOPIC_ARN)     – full plain-text report
  • Executive topic  (SNS_EXEC_TOPIC_ARN) – 5-line summary with posture score,
                                            24h trend, top 3 risks, remediation

Both topics receive data from a single Security Hub data collection pass.
All S3 outputs (report.json, executive_summary.md, CSVs, posture-snapshot)
are identical to lambda_function.py so nothing downstream changes.

USAGE
-----
1. Paste this file into a Lambda function in the console.
2. Edit the CONFIG section below (or set the corresponding env-vars).
3. Attach an IAM role with:
     securityhub:GetFindings
     securityhub:ListStandardsSubscriptions
     securityhub:DescribeStandardsControls
     sns:Publish    (on BOTH destination topics)
     s3:GetObject   (on <bucket>/<prefix>posture-snapshots/* — for trend)
     s3:PutObject   (on <bucket>/<prefix>*)
4. Schedule via EventBridge (same cron as lambda_function.py).
"""

# ============================================================
# CONFIG  –  edit these values or override via env-vars
# ============================================================
S3_BUCKET          = "variable"       # REPORT_BUCKET env-var overrides
S3_PREFIX          = "variable/"      # REPORT_PREFIX env-var overrides
SNS_TOPIC_ARN      = "variable"       # SNS_TOPIC_ARN env-var      → technical audience
SNS_EXEC_TOPIC_ARN = ""               # SNS_EXEC_TOPIC_ARN env-var → executive audience
LOOKBACK_HOURS     = 24               # LOOKBACK_HOURS env-var overrides
REGION             = "us-gov-west-1"  # SECURITY_HUB_REGION env-var overrides
DRY_RUN            = False
# ============================================================

import csv
import io
import json
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import boto3


# ---------------------------------------------------------------------------
# Helpers – configuration
# ---------------------------------------------------------------------------

def _cfg():
    def _env_bool(name, default):
        v = os.environ.get(name, "").strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
        return default

    bucket          = os.environ.get("REPORT_BUCKET",        S3_BUCKET).strip()
    prefix          = os.environ.get("REPORT_PREFIX",        S3_PREFIX).strip()
    topic_arn       = os.environ.get("SNS_TOPIC_ARN",        SNS_TOPIC_ARN      or "").strip()
    exec_topic_arn  = os.environ.get("SNS_EXEC_TOPIC_ARN",   SNS_EXEC_TOPIC_ARN or "").strip()
    lookback        = int(os.environ.get("LOOKBACK_HOURS",   str(LOOKBACK_HOURS)))
    region          = os.environ.get("SECURITY_HUB_REGION",  REGION or os.environ.get("AWS_REGION", "us-east-1")).strip()
    dry_run         = _env_bool("DRY_RUN", DRY_RUN)

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    return dict(
        bucket=bucket,
        prefix=prefix,
        topic_arn=topic_arn if topic_arn else None,
        exec_topic_arn=exec_topic_arn if exec_topic_arn else None,
        lookback_hours=lookback,
        region=region,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Helpers – time
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(tz=timezone.utc)


def _date_partition_prefix(cfg, dt):
    return f"{cfg['prefix']}{dt.strftime('%Y/%m/%d')}/"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Helpers – S3 writing
# ---------------------------------------------------------------------------

def _write_s3_bytes(s3_client, bucket, key, data, content_type="application/octet-stream", dry_run=False):
    if dry_run:
        print(json.dumps({"level": "INFO", "dry_run": True, "would_write_s3": f"s3://{bucket}/{key}",
                          "bytes": len(data)}))
        return
    s3_client.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type)


def _s3_get_json(s3_client, bucket, key):
    """Return parsed JSON from S3, or None on any error (including NoSuchKey)."""
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        return json.loads(resp["Body"].read())
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code != "NoSuchKey":
            print(json.dumps({"level": "WARNING", "step": "s3_get", "key": key, "error": str(exc)}))
        return None


# ---------------------------------------------------------------------------
# Helpers – CSV serialisation
# ---------------------------------------------------------------------------

def _csv_from_rows(headers, rows):
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Data collection – findings aggregations
# ---------------------------------------------------------------------------

def _collect_findings_aggregations(sh_client, cfg, execution_id):
    severity_counts       = defaultdict(int)
    workflow_counts       = defaultdict(int)
    product_counts        = defaultdict(int)
    account_region_counts = defaultdict(int)
    resource_type_counts  = defaultdict(int)
    control_counts        = defaultdict(int)

    total = 0
    api_calls = 0
    filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}

    next_token = None
    while True:
        params = dict(Filters=filters, MaxResults=100)
        if next_token:
            params["NextToken"] = next_token
        resp = sh_client.get_findings(**params)
        api_calls += 1

        for f in resp.get("Findings", []):
            total += 1
            severity_counts[(f.get("Severity") or {}).get("Label", "UNKNOWN")] += 1
            workflow_counts[(f.get("Workflow") or {}).get("Status", "UNKNOWN")] += 1
            prod = f.get("ProductName") or f.get("ProductArn", "Unknown").split("/")[-1]
            product_counts[prod] += 1
            acct = f.get("AwsAccountId", "Unknown")
            reg  = f.get("Region", cfg["region"])
            account_region_counts[(acct, reg)] += 1
            for res in f.get("Resources") or []:
                resource_type_counts[res.get("Type", "Unknown")] += 1
            pf   = f.get("ProductFields") or {}
            comp = f.get("Compliance") or {}
            ctrl_id = (
                comp.get("SecurityControlId")
                or pf.get("ControlId")
                or pf.get("RuleId")
                or f.get("GeneratorId", "Unknown")
            )
            if len(ctrl_id) > 80:
                ctrl_id = ctrl_id[:77] + "..."
            control_counts[(ctrl_id, f.get("Title", ""))] += 1

        next_token = resp.get("NextToken")
        if not next_token:
            break

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "collect_findings_aggregations",
        "total_findings": total, "api_calls": api_calls,
    }))
    return dict(
        total=total,
        severity_counts=dict(severity_counts),
        workflow_counts=dict(workflow_counts),
        product_counts=dict(product_counts),
        account_region_counts={f"{a}|{r}": c for (a, r), c in account_region_counts.items()},
        resource_type_counts=dict(resource_type_counts),
        control_counts={f"{cid}|||{ctitle}": cnt for (cid, ctitle), cnt in control_counts.items()},
        api_calls=api_calls,
    )


# ---------------------------------------------------------------------------
# Data collection – new and resolved findings in lookback window
# ---------------------------------------------------------------------------

def _collect_new_resolved(sh_client, cfg, execution_id):
    lookback_hours = cfg["lookback_hours"]
    cutoff = _utc_now() - timedelta(hours=lookback_hours)
    cutoff_iso = _iso(cutoff)
    now_iso = _iso(_utc_now() + timedelta(hours=1))

    def _count(extra_filters):
        count = 0
        api_calls = 0
        next_token = None
        while True:
            params = dict(Filters=extra_filters, MaxResults=100)
            if next_token:
                params["NextToken"] = next_token
            resp = sh_client.get_findings(**params)
            api_calls += 1
            count += len(resp.get("Findings", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return count, api_calls

    new_count, new_api = _count({
        "CreatedAt": [{"Start": cutoff_iso, "End": now_iso}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    })
    resolved_count, res_api = _count({
        "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "EQUALS"}],
        "UpdatedAt": [{"Start": cutoff_iso, "End": now_iso}],
    })

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "collect_new_resolved",
        "new_count": new_count, "resolved_count": resolved_count,
        "api_calls": new_api + res_api,
    }))
    return dict(
        lookback_hours=lookback_hours, cutoff_utc=cutoff_iso,
        new_count=new_count, resolved_count=resolved_count,
        api_calls=new_api + res_api,
    )


# ---------------------------------------------------------------------------
# Data collection – standards scores
# ---------------------------------------------------------------------------

def _list_standards_subscriptions(sh_client):
    for method_name in ("list_standards_subscriptions", "get_enabled_standards"):
        method = getattr(sh_client, method_name, None)
        if method is not None:
            return method()
    raise RuntimeError(
        "SecurityHub client has neither list_standards_subscriptions nor "
        "get_enabled_standards. Upgrade the boto3 Lambda layer or runtime."
    )


def _collect_standards_scores(sh_client, execution_id):
    scores = []
    api_calls = 0

    sub_resp = _list_standards_subscriptions(sh_client)
    api_calls += 1
    subscriptions = sub_resp.get("StandardsSubscriptions", [])

    for sub in subscriptions:
        arn    = sub["StandardsSubscriptionArn"]
        status = sub.get("StandardsStatus", "READY")
        if status != "READY":
            scores.append(dict(
                standard_arn=sub.get("StandardsArn", arn), subscription_arn=arn,
                status=status, total_enabled_controls=0, passed_controls=0,
                failed_controls=0, proxy_score=None, note="Standard not yet READY",
            ))
            continue

        total_enabled = passed = failed = 0
        next_token = None
        while True:
            params = dict(StandardsSubscriptionArn=arn, MaxResults=100)
            if next_token:
                params["NextToken"] = next_token
            ctrl_resp = sh_client.describe_standards_controls(**params)
            api_calls += 1
            for ctrl in ctrl_resp.get("Controls", []):
                if ctrl.get("ControlStatus") != "ENABLED":
                    continue
                total_enabled += 1
                cs = ctrl.get("ComplianceStatus", "")
                if cs == "PASSED":
                    passed += 1
                elif cs in ("FAILED", "WARNING"):
                    failed += 1
            next_token = ctrl_resp.get("NextToken")
            if not next_token:
                break

        scores.append(dict(
            standard_arn=sub.get("StandardsArn", arn), subscription_arn=arn,
            status=status, total_enabled_controls=total_enabled,
            passed_controls=passed, failed_controls=failed,
            proxy_score=round(100.0 * passed / max(total_enabled, 1), 2),
        ))

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "collect_standards_scores",
        "standards_evaluated": len(scores), "api_calls": api_calls,
    }))
    return scores, api_calls


# ---------------------------------------------------------------------------
# S3 posture snapshot
# ---------------------------------------------------------------------------

def _composite_score(standards):
    scores = [s["proxy_score"] for s in standards if s.get("proxy_score") is not None]
    return round(sum(scores) / len(scores), 2) if scores else None


def _save_posture_snapshot(s3_client, cfg, report_date, agg, nr, standards, execution_id):
    payload = {
        "date": report_date,
        "composite_posture_score": _composite_score(standards),
        "standards": [
            {
                "short_name": s["standard_arn"].split("/")[-1],
                "score": s.get("proxy_score"),
                "passed": s.get("passed_controls", 0),
                "total": s.get("total_enabled_controls", 0),
            }
            for s in standards
        ],
        "total_findings": agg["total"],
        "new_count": nr["new_count"],
        "resolved_count": nr["resolved_count"],
    }
    key = f"{cfg['prefix']}posture-snapshots/{report_date}.json"
    _write_s3_bytes(
        s3_client, cfg["bucket"], key,
        json.dumps(payload, indent=2).encode("utf-8"),
        content_type="application/json",
        dry_run=cfg["dry_run"],
    )
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "save_posture_snapshot",
        "s3_uri": f"s3://{cfg['bucket']}/{key}",
    }))


# ---------------------------------------------------------------------------
# Report builders
# ---------------------------------------------------------------------------

def _top_n(counter_dict, n=10):
    return sorted(counter_dict.items(), key=lambda kv: kv[1], reverse=True)[:n]


def _build_exec_summary(report_date_str, cfg, s3_prefix, agg, nr, standards):
    """Detailed markdown report → goes to S3 as executive_summary.md."""
    sev = agg["severity_counts"]
    wf  = agg["workflow_counts"]
    top_ctrl = _top_n(agg["control_counts"], 10)
    top_res  = _top_n(agg["resource_type_counts"], 10)

    lines = [
        "# AWS Security Hub – Daily Posture Report",
        f"**Report Date (UTC):** {report_date_str}",
        f"**S3 Output:** s3://{cfg['bucket']}/{s3_prefix}",
        f"**Lookback Window:** {cfg['lookback_hours']} hours",
        "", "---", "",
        "## Overall Findings",
        f"- **Total active findings:** {agg['total']:,}",
        "", "### By Severity",
    ]
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        lines.append(f"- {label}: {sev.get(label, 0):,}")
    lines += ["", "### By Workflow Status"]
    for k, v in sorted(wf.items()):
        lines.append(f"- {k}: {v:,}")
    lines += ["", "---", "", "## Standards Compliance Scores (Proxy)"]
    if standards:
        for s in standards:
            score_str = f"{s['proxy_score']}%" if s["proxy_score"] is not None else "N/A"
            lines.append(
                f"- **{s['standard_arn'].split('/')[-1]}**: {score_str} "
                f"({s['passed_controls']} passed / {s['total_enabled_controls']} enabled controls)"
            )
    else:
        lines.append("- No standards data available.")
    lines += ["", "---", "", "## Recent Activity"]
    lines.append(f"- **New findings (last {nr['lookback_hours']}h):** {nr['new_count']:,}")
    lines.append(f"- **Resolved findings (last {nr['lookback_hours']}h):** {nr['resolved_count']:,}")
    lines += ["", "---", "", "## Top 10 Failing Controls",
              "| Control ID / Generator | Title | Count |", "|---|---|---|"]
    for key, cnt in top_ctrl:
        parts = key.split("|||", 1)
        lines.append(f"| {parts[0]} | {parts[1][:80] if len(parts) > 1 else ''} | {cnt:,} |")
    lines += ["", "---", "", "## Top 10 Resource Types",
              "| Resource Type | Count |", "|---|---|"]
    for rtype, cnt in top_res:
        lines.append(f"| {rtype} | {cnt:,} |")
    lines += ["", "---", f"*Generated by Security Hub Multi-Audience Lambda – {_iso(_utc_now())}*"]
    return "\n".join(lines) + "\n"


def _build_technical_sns(report_date_str, cfg, s3_prefix, agg, nr, standards):
    """Full plain-text SNS message for the technical audience."""
    sev = agg["severity_counts"]
    wf  = agg["workflow_counts"]
    top_ctrl = _top_n(agg["control_counts"], 10)
    top_res  = _top_n(agg["resource_type_counts"], 10)

    lines = [
        f"AWS Security Hub Daily Posture Report – {report_date_str}",
        "=" * 60,
        "",
        f"Report Date (UTC) : {report_date_str}",
        f"S3 Output         : s3://{cfg['bucket']}/{s3_prefix}",
        f"Lookback Window   : {cfg['lookback_hours']} hours",
        "",
        "OVERALL FINDINGS",
        f"  Total active findings : {agg['total']:,}",
        "",
        "BY SEVERITY",
    ]
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        lines.append(f"  {label:<15}: {sev.get(label, 0):,}")
    lines += ["", "BY WORKFLOW STATUS"]
    for k, v in sorted(wf.items()):
        lines.append(f"  {k:<15}: {v:,}")
    lines += ["", "STANDARDS COMPLIANCE SCORES (Proxy)"]
    if standards:
        for s in standards:
            score_str = f"{s['proxy_score']}%" if s["proxy_score"] is not None else "N/A"
            lines.append(
                f"  {s['standard_arn'].split('/')[-1]}: {score_str} "
                f"({s['passed_controls']} passed / {s['total_enabled_controls']} enabled)"
            )
    else:
        lines.append("  No standards data available.")
    lines += [
        "",
        "RECENT ACTIVITY",
        f"  New findings (last {nr['lookback_hours']}h)     : {nr['new_count']:,}",
        f"  Resolved findings (last {nr['lookback_hours']}h) : {nr['resolved_count']:,}",
        "",
        "TOP 10 FAILING CONTROLS",
    ]
    for i, (key, cnt) in enumerate(top_ctrl, 1):
        ctrl_id = key.split("|||")[0]
        title   = key.split("|||")[1] if "|||" in key else ""
        lines.append(f"  {i:2}. [{cnt:,}] {ctrl_id} – {title[:70]}")
    lines += ["", "TOP 10 RESOURCE TYPES"]
    for i, (rtype, cnt) in enumerate(top_res, 1):
        lines.append(f"  {i:2}. [{cnt:,}] {rtype}")
    lines += ["", "=" * 60, "Generated by Security Hub Multi-Audience Lambda"]
    return "\n".join(lines)


def _build_exec_sns(report_date_str, cfg, agg, nr, standards, prev_snapshot=None):
    """
    5-line executive SNS summary (plain text — renders in any email client).

    Example:
    ════════════════════════════════════════════════════════
    Security Hub Executive Summary – 2026-03-09
    ════════════════════════════════════════════════════════
    Posture Score  : 78.5%  (↑ +2.3pp vs yesterday)
    Findings       : 1,234 active  |  47 new / 52 resolved  → net -5 (improving)
    Top 3 Controls : [EC2.1] (143 open)  |  [IAM.4] (87)  |  [S3.2] (64)
    Remediation    : 52 findings closed in last 24h
    Standards      : aws-foundational-security-best-practices: 78.5%
    ════════════════════════════════════════════════════════
    """
    composite = _composite_score(standards)

    # Posture score + optional yesterday trend
    if composite is not None:
        score_str = f"{composite}%"
        if prev_snapshot and prev_snapshot.get("composite_posture_score") is not None:
            delta = round(composite - prev_snapshot["composite_posture_score"], 1)
            arrow = "↑" if delta >= 0 else "↓"
            score_str += f"  ({arrow} {delta:+.1f}pp vs yesterday)"
    else:
        score_str = "N/A"

    # Activity / trend line
    net = nr["resolved_count"] - nr["new_count"]
    trend_word = "improving" if net > 0 else ("stable" if net == 0 else "worsening")
    activity = (
        f"{agg['total']:,} active  |  "
        f"{nr['new_count']:,} new / {nr['resolved_count']:,} resolved  "
        f"→ net {net:+d} ({trend_word})"
    )

    # Top 3 failing controls
    top3_parts = []
    for key, cnt in _top_n(agg["control_counts"], 3):
        ctrl_id = key.split("|||")[0]
        top3_parts.append(f"[{ctrl_id}] ({cnt:,} open)")
    top3_str = "  |  ".join(top3_parts) if top3_parts else "None"

    # Standards one-liner
    std_parts = [
        f"{s['standard_arn'].split('/')[-1]}: {s['proxy_score']}%"
        for s in standards if s.get("proxy_score") is not None
    ]
    std_str = "  |  ".join(std_parts) if std_parts else "N/A"

    sev = agg["severity_counts"]
    critical = sev.get("CRITICAL", 0)
    action = (
        f"{critical:,} CRITICAL findings require immediate attention"
        if critical else "No CRITICAL findings"
    )

    sep = "=" * 56
    lines = [
        sep,
        f"Security Hub Executive Summary – {report_date_str}",
        sep,
        f"Posture Score  : {score_str}",
        f"Findings       : {activity}",
        f"Top 3 Controls : {top3_str}",
        f"Remediation    : {nr['resolved_count']:,} findings closed in last {cfg['lookback_hours']}h",
        f"Standards      : {std_str}",
        "-" * 56,
        f"Action Items   : {action}",
        sep,
        "Full technical report sent to security-team list.",
        f"Generated: {_iso(_utc_now())}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SNS publish helper
# ---------------------------------------------------------------------------

def _publish_sns(sns_client, topic_arn, subject, message, dry_run=False):
    if dry_run:
        print(json.dumps({
            "level": "INFO", "dry_run": True,
            "would_publish_sns": True, "subject": subject,
            "message_preview": message[:500],
        }))
        return False
    sns_client.publish(TopicArn=topic_arn, Subject=subject[:100], Message=message)
    return True


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    execution_id = getattr(context, "aws_request_id", str(uuid.uuid4()))
    start_time   = time.time()

    print(json.dumps({"level": "INFO", "execution_id": execution_id, "step": "start"}))

    cfg = _cfg()

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "config_resolved",
        "bucket": cfg["bucket"], "prefix": cfg["prefix"],
        "region": cfg["region"], "lookback_hours": cfg["lookback_hours"],
        "sns_topic_arn": cfg["topic_arn"] or "DISABLED",
        "sns_exec_topic_arn": cfg["exec_topic_arn"] or "DISABLED",
        "dry_run": cfg["dry_run"],
    }))

    sh_client  = boto3.client("securityhub", region_name=cfg["region"])
    s3_client  = boto3.client("s3")
    sns_client = boto3.client("sns", region_name=cfg["region"])

    now            = _utc_now()
    report_date    = now.strftime("%Y-%m-%d")
    yesterday      = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    s3_date_prefix = _date_partition_prefix(cfg, now)
    errors         = []

    # 1. Findings aggregations
    try:
        agg = _collect_findings_aggregations(sh_client, cfg, execution_id)
    except Exception as exc:
        err = {"step": "collect_findings_aggregations", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        agg = dict(
            total=0, severity_counts={}, workflow_counts={}, product_counts={},
            account_region_counts={}, resource_type_counts={}, control_counts={}, api_calls=0,
        )

    # 2. New / resolved in lookback window
    try:
        nr = _collect_new_resolved(sh_client, cfg, execution_id)
    except Exception as exc:
        err = {"step": "collect_new_resolved", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        nr = dict(lookback_hours=cfg["lookback_hours"], cutoff_utc="", new_count=0, resolved_count=0, api_calls=0)

    # 3. Standards scores
    try:
        standards, std_api_calls = _collect_standards_scores(sh_client, execution_id)
    except Exception as exc:
        err = {"step": "collect_standards_scores", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        standards     = []
        std_api_calls = 0

    # 4. Load yesterday's snapshot for executive trend (best-effort, no failure if missing)
    prev_snapshot = _s3_get_json(
        s3_client, cfg["bucket"],
        f"{cfg['prefix']}posture-snapshots/{yesterday}.json"
    )

    # 5. Save today's posture snapshot
    try:
        _save_posture_snapshot(s3_client, cfg, report_date, agg, nr, standards, execution_id)
    except Exception as exc:
        err = {"step": "save_posture_snapshot", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    # ------------------------------------------------------------------
    # Build reports
    # ------------------------------------------------------------------
    top_controls       = _top_n(agg["control_counts"], 10)
    top_resource_types = _top_n(agg["resource_type_counts"], 10)

    exec_summary_md = _build_exec_summary(report_date, cfg, s3_date_prefix, agg, nr, standards)

    # ------------------------------------------------------------------
    # Build and write CSVs + full report JSON to S3
    # ------------------------------------------------------------------
    report = {
        "report_date":    report_date,
        "generated_at":   _iso(now),
        "execution_id":   execution_id,
        "s3_bucket":      cfg["bucket"],
        "s3_prefix":      cfg["prefix"],
        "s3_date_prefix": s3_date_prefix,
        "lookback_hours": cfg["lookback_hours"],
        "region":         cfg["region"],
        "dry_run":        cfg["dry_run"],
        "totals": {
            "overall":     agg["total"],
            "by_severity": agg["severity_counts"],
            "by_workflow": agg["workflow_counts"],
        },
        "by_product":           agg["product_counts"],
        "by_account_region":    agg["account_region_counts"],
        "by_resource_type":     agg["resource_type_counts"],
        "top_controls":         [{"key": k, "count": v} for k, v in top_controls],
        "top_resource_types":   [{"type": k, "count": v} for k, v in top_resource_types],
        "new_count_last_lookback":      nr["new_count"],
        "resolved_count_last_lookback": nr["resolved_count"],
        "standards_scores":     standards,
        "errors":               errors,
    }

    acct_reg_rows = []
    for key, cnt in sorted(agg["account_region_counts"].items(), key=lambda x: x[1], reverse=True):
        parts = key.split("|", 1)
        acct_reg_rows.append([parts[0], parts[1] if len(parts) > 1 else "", cnt])

    ctrl_rows = []
    for key, cnt in top_controls:
        parts = key.split("|||", 1)
        ctrl_rows.append([parts[0], parts[1] if len(parts) > 1 else "", cnt])

    files_to_write = [
        ("report.json",
         json.dumps(report, indent=2, default=str), "application/json"),
        ("executive_summary.md",
         exec_summary_md, "text/markdown"),
        ("findings_by_severity.csv",
         _csv_from_rows(["severity", "count"], sorted(agg["severity_counts"].items())), "text/csv"),
        ("findings_by_workflow.csv",
         _csv_from_rows(["workflow_status", "count"], sorted(agg["workflow_counts"].items())), "text/csv"),
        ("findings_by_product.csv",
         _csv_from_rows(["product_name", "count"],
                        sorted(agg["product_counts"].items(), key=lambda x: x[1], reverse=True)), "text/csv"),
        ("findings_by_account_region.csv",
         _csv_from_rows(["account_id", "region", "count"], acct_reg_rows), "text/csv"),
        ("top_failing_controls.csv",
         _csv_from_rows(["control_id", "title", "count"], ctrl_rows), "text/csv"),
        ("top_resource_types.csv",
         _csv_from_rows(["resource_type", "count"], [[rt, cnt] for rt, cnt in top_resource_types]), "text/csv"),
        (f"new_last_{cfg['lookback_hours']}h.csv",
         _csv_from_rows(["metric", "value"],
                        [["lookback_hours", nr["lookback_hours"]], ["cutoff_utc", nr["cutoff_utc"]],
                         ["new_findings", nr["new_count"]]]), "text/csv"),
        (f"resolved_last_{cfg['lookback_hours']}h.csv",
         _csv_from_rows(["metric", "value"],
                        [["lookback_hours", nr["lookback_hours"]], ["cutoff_utc", nr["cutoff_utc"]],
                         ["resolved_findings", nr["resolved_count"]]]), "text/csv"),
    ]

    written_keys = []
    for filename, content, ctype in files_to_write:
        key = s3_date_prefix + filename
        try:
            _write_s3_bytes(s3_client, cfg["bucket"], key,
                            content.encode("utf-8"), content_type=ctype, dry_run=cfg["dry_run"])
            written_keys.append(key)
        except Exception as exc:
            err = {"step": "write_s3", "key": key, "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "s3_writes_complete",
        "files_written": len(written_keys), "dry_run": cfg["dry_run"],
    }))

    if errors:
        error_section = "\n\nERRORS DURING COLLECTION:\n" + "".join(
            f"  - {e['step']}: {e['error']}\n" for e in errors
        )
    else:
        error_section = ""

    # ------------------------------------------------------------------
    # Publish to technical SNS topic (full report)
    # ------------------------------------------------------------------
    tech_published = False
    if cfg["topic_arn"]:
        tech_body = _build_technical_sns(report_date, cfg, s3_date_prefix, agg, nr, standards)
        if error_section:
            tech_body += error_section
        try:
            tech_published = _publish_sns(
                sns_client, cfg["topic_arn"],
                f"Security Hub Daily Report – {report_date}",
                tech_body, dry_run=cfg["dry_run"],
            )
            print(json.dumps({
                "level": "INFO", "execution_id": execution_id,
                "step": "sns_publish_technical", "published": tech_published,
            }))
        except Exception as exc:
            err = {"step": "sns_publish_technical", "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    # ------------------------------------------------------------------
    # Publish to executive SNS topic (5-line summary)
    # ------------------------------------------------------------------
    exec_published = False
    if cfg["exec_topic_arn"]:
        exec_body = _build_exec_sns(report_date, cfg, agg, nr, standards, prev_snapshot)
        if error_section:
            exec_body += error_section
        try:
            exec_published = _publish_sns(
                sns_client, cfg["exec_topic_arn"],
                f"Security Hub Executive Summary – {report_date}",
                exec_body, dry_run=cfg["dry_run"],
            )
            print(json.dumps({
                "level": "INFO", "execution_id": execution_id,
                "step": "sns_publish_executive", "published": exec_published,
            }))
        except Exception as exc:
            err = {"step": "sns_publish_executive", "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    elapsed = round(time.time() - start_time, 3)
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "complete", "elapsed_seconds": elapsed,
        "total_findings": agg["total"],
        "files_written": len(written_keys),
        "tech_published": tech_published,
        "exec_published": exec_published,
        "errors": len(errors),
    }))

    return {
        "report_date":     report_date,
        "s3_bucket":       cfg["bucket"],
        "s3_prefix_written": s3_date_prefix,
        "totals": {
            "overall":     agg["total"],
            "by_severity": agg["severity_counts"],
            "by_workflow": agg["workflow_counts"],
        },
        "new_count_last_lookback":      nr["new_count"],
        "resolved_count_last_lookback": nr["resolved_count"],
        "tech_published":  tech_published,
        "exec_published":  exec_published,
        "errors":          errors,
    }
