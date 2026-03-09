"""
AWS Security Hub Daily Posture Report – Lambda Function
Python 3.12 + boto3

PURPOSE
-------
Fetches Security Hub findings and control/standard scores, then publishes
a plain-text summary report to SNS (email-friendly).

USAGE
-----
1. Paste this file into the Lambda console.
2. Edit the CONFIG section below (or set the corresponding env-vars).
3. Attach an IAM role with:
     securityhub:GetFindings
     securityhub:ListStandardsSubscriptions
     securityhub:DescribeStandardsControls
     sns:Publish   (on the destination topic)
"""

# ============================================================
# CONFIG  –  edit these values or override via env-vars
# ============================================================
SNS_TOPIC_ARN   = ""     # Set via SNS_TOPIC_ARN env-var (required)
S3_BUCKET_NAME  = ""     # Set via S3_BUCKET_NAME env-var (optional, for report archival)
LOOKBACK_HOURS  = 24     # LOOKBACK_HOURS env-var overrides
REGION          = ""     # Set via SECURITY_HUB_REGION or AWS_REGION env-var
DRY_RUN         = False                              # DRY_RUN env-var ("true"/"1") overrides
# ============================================================

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
    """Return resolved configuration dict (env-vars take precedence)."""
    def _env_bool(name, default):
        v = os.environ.get(name, "").strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
        return default

    topic_arn   = os.environ.get("SNS_TOPIC_ARN",        SNS_TOPIC_ARN or "").strip()
    bucket_name = os.environ.get("S3_BUCKET_NAME",       S3_BUCKET_NAME or "").strip()
    lookback    = int(os.environ.get("LOOKBACK_HOURS",   str(LOOKBACK_HOURS)))
    region      = os.environ.get("SECURITY_HUB_REGION",  REGION or os.environ.get("AWS_REGION", "")).strip()
    dry_run     = _env_bool("DRY_RUN", DRY_RUN)

    return dict(
        topic_arn=topic_arn if topic_arn else None,
        bucket_name=bucket_name if bucket_name else None,
        lookback_hours=lookback,
        region=region,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Helpers – time
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(tz=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Data collection – findings aggregations
# ---------------------------------------------------------------------------

def _collect_findings_aggregations(sh_client, cfg, execution_id):
    """
    Page through ALL active findings (RecordState == ACTIVE) and accumulate
    counts by severity, workflow status, product, account/region, resource
    type, and control ID.
    """
    severity_counts       = defaultdict(int)
    workflow_counts       = defaultdict(int)
    product_counts        = defaultdict(int)
    account_region_counts = defaultdict(int)
    resource_type_counts  = defaultdict(int)
    control_counts        = defaultdict(int)

    total = 0
    api_calls = 0

    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }

    next_token = None
    while True:
        params = dict(Filters=filters, MaxResults=100)
        if next_token:
            params["NextToken"] = next_token
        resp = sh_client.get_findings(**params)
        api_calls += 1

        for f in resp.get("Findings", []):
            total += 1

            sev = (f.get("Severity") or {}).get("Label", "UNKNOWN")
            severity_counts[sev] += 1

            wf = (f.get("Workflow") or {}).get("Status", "UNKNOWN")
            workflow_counts[wf] += 1

            prod = f.get("ProductName") or f.get("ProductArn", "Unknown").split("/")[-1]
            product_counts[prod] += 1

            acct = f.get("AwsAccountId", "Unknown")
            reg  = f.get("Region", cfg["region"])
            account_region_counts[(acct, reg)] += 1

            for res in f.get("Resources") or []:
                rtype = res.get("Type", "Unknown")
                resource_type_counts[rtype] += 1

            pf      = f.get("ProductFields") or {}
            comp    = f.get("Compliance") or {}
            ctrl_id = (
                comp.get("SecurityControlId")
                or pf.get("ControlId")
                or pf.get("RuleId")
                or f.get("GeneratorId", "Unknown")
            )
            ctrl_title = f.get("Title", "")
            if len(ctrl_id) > 80:
                ctrl_id = ctrl_id[:77] + "..."
            control_counts[(ctrl_id, ctrl_title)] += 1

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
    )


# ---------------------------------------------------------------------------
# Data collection – new and resolved findings in lookback window
# ---------------------------------------------------------------------------

def _collect_new_resolved(sh_client, cfg, execution_id):
    lookback_hours = cfg["lookback_hours"]
    cutoff = _utc_now() - timedelta(hours=lookback_hours)
    cutoff_iso = _iso(cutoff)
    now_iso = _iso(_utc_now() + timedelta(hours=1))

    def _count_with_filter(extra_filters):
        count = 0
        next_token = None
        while True:
            params = dict(Filters=extra_filters, MaxResults=100)
            if next_token:
                params["NextToken"] = next_token
            resp = sh_client.get_findings(**params)
            count += len(resp.get("Findings", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return count

    new_count = _count_with_filter({
        "CreatedAt": [{"Start": cutoff_iso, "End": now_iso}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    })

    resolved_count = _count_with_filter({
        "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "EQUALS"}],
        "UpdatedAt": [{"Start": cutoff_iso, "End": now_iso}],
    })

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "collect_new_resolved",
        "new_count": new_count, "resolved_count": resolved_count,
    }))

    return dict(
        lookback_hours=lookback_hours,
        cutoff_utc=cutoff_iso,
        new_count=new_count,
        resolved_count=resolved_count,
    )


# ---------------------------------------------------------------------------
# Data collection – standards scores
# ---------------------------------------------------------------------------

def _collect_standards_scores(sh_client, execution_id):
    scores = []
    api_calls = 0

    sub_resp = sh_client.list_standards_subscriptions()
    api_calls += 1
    subscriptions = sub_resp.get("StandardsSubscriptions", [])

    for sub in subscriptions:
        arn    = sub["StandardsSubscriptionArn"]
        status = sub.get("StandardsStatus", "READY")

        if status != "READY":
            scores.append(dict(
                standard_arn=sub.get("StandardsArn", arn),
                status=status, total_enabled_controls=0,
                passed_controls=0, failed_controls=0,
                proxy_score=None, note="Standard not yet READY",
            ))
            continue

        total_enabled = 0
        passed        = 0
        failed        = 0

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

        proxy_score = round(100.0 * passed / max(total_enabled, 1), 2)

        scores.append(dict(
            standard_arn=sub.get("StandardsArn", arn),
            status=status, total_enabled_controls=total_enabled,
            passed_controls=passed, failed_controls=failed,
            proxy_score=proxy_score,
        ))

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "collect_standards_scores",
        "standards_evaluated": len(scores),
    }))

    return scores


# ---------------------------------------------------------------------------
# Email report builder
# ---------------------------------------------------------------------------

def _top_n(counter_dict, n=10):
    return sorted(counter_dict.items(), key=lambda kv: kv[1], reverse=True)[:n]


def _build_email(report_date_str, cfg, agg, nr, standards):
    """Build the plain-text email body with the full report."""
    sev = agg["severity_counts"]
    wf  = agg["workflow_counts"]
    top_ctrl = _top_n(agg["control_counts"], 10)
    top_res  = _top_n(agg["resource_type_counts"], 10)
    top_prod = _top_n(agg["product_counts"], 10)

    lines = [
        f"AWS Security Hub Daily Posture Report",
        f"Report Date (UTC): {report_date_str}",
        f"Lookback Window  : {cfg['lookback_hours']} hours",
        "=" * 60,
        "",
        "OVERALL FINDINGS",
        f"  Total active findings: {agg['total']:,}",
        "",
        "BY SEVERITY",
    ]
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        lines.append(f"  {label:<15}: {sev.get(label, 0):,}")

    lines += ["", "BY WORKFLOW STATUS"]
    for k, v in sorted(wf.items()):
        lines.append(f"  {k:<15}: {v:,}")

    lines += ["", "-" * 60, "", "STANDARDS COMPLIANCE SCORES"]
    if standards:
        for s in standards:
            score_str = f"{s['proxy_score']}%" if s["proxy_score"] is not None else "N/A"
            arn_short = s["standard_arn"].split("/")[-1]
            lines.append(
                f"  {arn_short}: {score_str} "
                f"({s['passed_controls']} passed / {s['total_enabled_controls']} enabled, "
                f"{s['failed_controls']} failed)"
            )
    else:
        lines.append("  No standards data available.")

    lines += [
        "",
        "-" * 60,
        "",
        "RECENT ACTIVITY",
        f"  New findings (last {nr['lookback_hours']}h)     : {nr['new_count']:,}",
        f"  Resolved findings (last {nr['lookback_hours']}h) : {nr['resolved_count']:,}",
        "",
        "-" * 60,
        "",
        "TOP 10 FAILING CONTROLS",
    ]
    for i, (key, cnt) in enumerate(top_ctrl, 1):
        ctrl_id = key.split("|||")[0]
        title   = key.split("|||")[1] if "|||" in key else ""
        lines.append(f"  {i:2}. [{cnt:,}] {ctrl_id}")
        if title:
            lines.append(f"      {title[:80]}")

    lines += ["", "-" * 60, "", "TOP 10 RESOURCE TYPES"]
    for i, (rtype, cnt) in enumerate(top_res, 1):
        lines.append(f"  {i:2}. [{cnt:,}] {rtype}")

    lines += ["", "-" * 60, "", "TOP 10 PRODUCTS"]
    for i, (prod, cnt) in enumerate(top_prod, 1):
        lines.append(f"  {i:2}. [{cnt:,}] {prod}")

    # Account/region breakdown
    acct_region = agg["account_region_counts"]
    if acct_region:
        lines += ["", "-" * 60, "", "FINDINGS BY ACCOUNT / REGION"]
        sorted_ar = sorted(acct_region.items(), key=lambda x: x[1], reverse=True)
        for key, cnt in sorted_ar:
            parts = key.split("|", 1)
            acct  = parts[0]
            reg   = parts[1] if len(parts) > 1 else ""
            lines.append(f"  {acct} / {reg}: {cnt:,}")

    lines += [
        "",
        "=" * 60,
        f"Generated by Security Hub Daily Posture Lambda – {_iso(_utc_now())}",
    ]

    return "\n".join(lines)


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
        "region": cfg["region"],
        "lookback_hours": cfg["lookback_hours"],
        "sns_topic_arn": cfg["topic_arn"] or "DISABLED",
        "dry_run": cfg["dry_run"],
    }))

    sh_client  = boto3.client("securityhub", region_name=cfg["region"])
    sns_client = boto3.client("sns", region_name=cfg["region"])

    now         = _utc_now()
    report_date = now.strftime("%Y-%m-%d")

    errors = []

    # 1. Findings aggregations
    try:
        agg = _collect_findings_aggregations(sh_client, cfg, execution_id)
    except Exception as exc:
        err = {"step": "collect_findings_aggregations", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        agg = dict(
            total=0, severity_counts={}, workflow_counts={}, product_counts={},
            account_region_counts={}, resource_type_counts={}, control_counts={},
        )

    # 2. New / resolved in lookback window
    try:
        nr = _collect_new_resolved(sh_client, cfg, execution_id)
    except Exception as exc:
        err = {"step": "collect_new_resolved", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        nr = dict(lookback_hours=cfg["lookback_hours"], cutoff_utc="", new_count=0, resolved_count=0)

    # 3. Standards scores
    try:
        standards = _collect_standards_scores(sh_client, execution_id)
    except Exception as exc:
        err = {"step": "collect_standards_scores", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        standards = []

    # Build and send email
    email_body = _build_email(report_date, cfg, agg, nr, standards)

    if errors:
        email_body += "\n\nERRORS DURING COLLECTION:\n"
        for e in errors:
            email_body += f"  - {e['step']}: {e['error']}\n"

    sns_published = False
    if cfg["topic_arn"]:
        subject = f"Security Hub Daily Report – {report_date}"
        try:
            if cfg["dry_run"]:
                print(json.dumps({
                    "level": "INFO", "dry_run": True,
                    "would_publish_sns": True, "subject": subject,
                    "message_preview": email_body[:500],
                }))
            else:
                sns_client.publish(
                    TopicArn=cfg["topic_arn"],
                    Subject=subject[:100],
                    Message=email_body,
                )
                sns_published = True
            print(json.dumps({
                "level": "INFO", "execution_id": execution_id,
                "step": "sns_publish", "published": sns_published,
            }))
        except Exception as exc:
            err = {"step": "sns_publish", "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
    else:
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "sns_publish", "skipped": True,
            "reason": "SNS_TOPIC_ARN not configured",
        }))

    elapsed = round(time.time() - start_time, 3)
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "complete", "elapsed_seconds": elapsed,
        "total_findings": agg["total"],
        "sns_published": sns_published, "errors": len(errors),
    }))

    return {
        "report_date":    report_date,
        "total_findings": agg["total"],
        "new_count":      nr["new_count"],
        "resolved_count": nr["resolved_count"],
        "sns_published":  sns_published,
        "errors":         errors,
    }
