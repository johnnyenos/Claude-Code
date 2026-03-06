"""
AWS Security Hub Daily Posture Report – Lambda Function
Python 3.12 + boto3

PURPOSE
-------
Fetches Security Hub findings and control/standard scores, writes structured
reports to S3, and publishes a plain-text summary to SNS (email-friendly).

USAGE
-----
1. Paste this file into the Lambda console.
2. Edit the CONFIG section below (or set the corresponding env-vars).
3. Attach an IAM role with:
     securityhub:GetFindings
     securityhub:ListStandardsSubscriptions
     securityhub:DescribeStandardsControls
     s3:PutObject  (on the destination bucket)
     sns:Publish   (on the destination topic)
"""

# ============================================================
# CONFIG  –  edit these values or override via env-vars
# ============================================================
S3_BUCKET       = "REPLACE_ME"           # REPORT_BUCKET env-var overrides
S3_PREFIX       = "securityhub-reports/" # REPORT_PREFIX env-var overrides
SNS_TOPIC_ARN   = "REPLACE_ME"           # SNS_TOPIC_ARN env-var overrides; blank/None disables
LOOKBACK_HOURS  = 24                     # LOOKBACK_HOURS env-var overrides
REGION          = None                   # SECURITY_HUB_REGION env-var overrides; None → AWS_REGION
DRY_RUN         = False                  # DRY_RUN env-var ("true"/"1") overrides
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
    """Return resolved configuration dict (env-vars take precedence)."""
    def _env_bool(name, default):
        v = os.environ.get(name, "").strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
        return default

    bucket      = os.environ.get("REPORT_BUCKET",         S3_BUCKET).strip()
    prefix      = os.environ.get("REPORT_PREFIX",         S3_PREFIX).strip()
    topic_arn   = os.environ.get("SNS_TOPIC_ARN",         SNS_TOPIC_ARN or "").strip()
    lookback    = int(os.environ.get("LOOKBACK_HOURS",    str(LOOKBACK_HOURS)))
    region      = os.environ.get("SECURITY_HUB_REGION",  REGION or os.environ.get("AWS_REGION", "us-east-1")).strip()
    dry_run     = _env_bool("DRY_RUN", DRY_RUN)

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    return dict(
        bucket=bucket,
        prefix=prefix,
        topic_arn=topic_arn if topic_arn else None,
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
    """
    Return the full S3 key prefix for today's partition.
    e.g. securityhub-reports/2025/07/15/
    """
    return f"{cfg['prefix']}{dt.strftime('%Y/%m/%d')}/"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Helpers – pagination
# ---------------------------------------------------------------------------

def _paginate(client_method, result_key, **kwargs):
    """
    Generic paginator for boto3 calls that use NextToken / Marker.
    Yields individual items from result_key list.
    """
    token = None
    while True:
        params = {k: v for k, v in kwargs.items()}
        if token:
            params["NextToken"] = token
        response = client_method(**params)
        for item in response.get(result_key, []):
            yield item
        token = response.get("NextToken")
        if not token:
            break


# ---------------------------------------------------------------------------
# Helpers – S3 writing
# ---------------------------------------------------------------------------

def _write_s3_text(s3_client, bucket, key, text, dry_run=False):
    if dry_run:
        print(json.dumps({"level": "INFO", "dry_run": True, "would_write_s3": f"s3://{bucket}/{key}",
                          "bytes": len(text.encode())}))
        return
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=text.encode("utf-8"),
        ContentType="text/plain; charset=utf-8",
    )


def _write_s3_bytes(s3_client, bucket, key, data, content_type="application/octet-stream", dry_run=False):
    if dry_run:
        print(json.dumps({"level": "INFO", "dry_run": True, "would_write_s3": f"s3://{bucket}/{key}",
                          "bytes": len(data)}))
        return
    s3_client.put_object(Bucket=bucket, Key=key, Body=data, ContentType=content_type)


# ---------------------------------------------------------------------------
# Helpers – CSV serialisation
# ---------------------------------------------------------------------------

def _csv_from_rows(headers, rows):
    """Return CSV string from a list of header names and list-of-list rows."""
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
    """
    Page through ALL active findings (RecordState == ACTIVE) and accumulate
    counts for:
      - severity_counts      {label: int}
      - workflow_counts      {status: int}
      - product_counts       {product_name: int}
      - account_region_counts {(account_id, region): int}
      - resource_type_counts {resource_type: int}
      - control_counts       {(control_id, title): int}  ← "top failing controls"

    API used:
      securityhub:GetFindings
      Filter: RecordState = ACTIVE
      Fields used per finding:
        Severity.Label, Workflow.Status, ProductName,
        AwsAccountId, Region, Resources[].Type,
        Compliance.RelatedRequirements / ProductFields["ControlId"] /
        ProductFields["aws/securityhub/FindingId"] / GeneratorId
        (control_id extraction – see inline comments)

    Findings are NOT stored in memory; only counters are kept.
    """
    severity_counts       = defaultdict(int)
    workflow_counts       = defaultdict(int)
    product_counts        = defaultdict(int)
    account_region_counts = defaultdict(int)
    resource_type_counts  = defaultdict(int)
    control_counts        = defaultdict(int)

    total = 0
    api_calls = 0

    # We use manual pagination because the boto3 paginator for GetFindings
    # uses a slightly different structure.
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

            # Severity
            sev = (f.get("Severity") or {}).get("Label", "UNKNOWN")
            severity_counts[sev] += 1

            # Workflow status
            wf = (f.get("Workflow") or {}).get("Status", "UNKNOWN")
            workflow_counts[wf] += 1

            # Product name
            prod = f.get("ProductName") or f.get("ProductArn", "Unknown").split("/")[-1]
            product_counts[prod] += 1

            # Account + region
            acct   = f.get("AwsAccountId", "Unknown")
            reg    = f.get("Region", cfg["region"])
            account_region_counts[(acct, reg)] += 1

            # Resource types (a finding can reference multiple resources)
            for res in f.get("Resources") or []:
                rtype = res.get("Type", "Unknown")
                resource_type_counts[rtype] += 1

            # Control ID / title for "top failing controls"
            # Priority order:
            #   1. Compliance.SecurityControlId  (most direct – added in newer API)
            #   2. ProductFields["ControlId"]    (common in older FSBP findings)
            #   3. ProductFields["RuleId"]       (CIS findings)
            #   4. GeneratorId                   (fallback – often contains control ref)
            #
            # Title: Compliance.RelatedRequirements[0] or finding Title field.
            pf      = f.get("ProductFields") or {}
            comp    = f.get("Compliance") or {}
            ctrl_id = (
                comp.get("SecurityControlId")
                or pf.get("ControlId")
                or pf.get("RuleId")
                or f.get("GeneratorId", "Unknown")
            )
            ctrl_title = f.get("Title", "")
            # Trim long GeneratorId values so CSV stays readable
            if len(ctrl_id) > 80:
                ctrl_id = ctrl_id[:77] + "..."
            control_counts[(ctrl_id, ctrl_title)] += 1

        next_token = resp.get("NextToken")
        if not next_token:
            break

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "collect_findings_aggregations",
        "total_findings": total,
        "api_calls": api_calls,
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
    """
    Collect summary counts of:
      - NEW findings:      CreatedAt >= (now - LOOKBACK_HOURS)
      - RESOLVED findings: Workflow.Status == RESOLVED
                           AND UpdatedAt >= (now - LOOKBACK_HOURS)

    API used:
      securityhub:GetFindings  with date-range Filters
      Fields: CreatedAt, UpdatedAt, Workflow.Status
    """
    lookback_hours = cfg["lookback_hours"]
    cutoff = _utc_now() - timedelta(hours=lookback_hours)
    cutoff_iso = _iso(cutoff)
    now_iso = _iso(_utc_now() + timedelta(hours=1))  # slight buffer for "end"

    def _count_with_filter(extra_filters):
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

    # New findings: CreatedAt within lookback window
    new_filters = {
        "CreatedAt": [{"Start": cutoff_iso, "End": now_iso, "DateRange": None}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }
    # Remove DateRange key since we're using Start/End
    new_filters["CreatedAt"] = [{"Start": cutoff_iso, "End": now_iso}]

    new_count, new_api = _count_with_filter(new_filters)

    # Resolved findings: Workflow.Status == RESOLVED AND UpdatedAt within window
    resolved_filters = {
        "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "EQUALS"}],
        "UpdatedAt": [{"Start": cutoff_iso, "End": now_iso}],
    }
    resolved_count, res_api = _count_with_filter(resolved_filters)

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "collect_new_resolved",
        "lookback_hours": lookback_hours,
        "cutoff_utc": cutoff_iso,
        "new_count": new_count,
        "resolved_count": resolved_count,
        "api_calls": new_api + res_api,
    }))

    return dict(
        lookback_hours=lookback_hours,
        cutoff_utc=cutoff_iso,
        new_count=new_count,
        resolved_count=resolved_count,
        api_calls=new_api + res_api,
    )


# ---------------------------------------------------------------------------
# Data collection – standards scores
# ---------------------------------------------------------------------------

def _collect_standards_scores(sh_client, execution_id):
    """
    Compute a proxy compliance score per enabled Security Hub standard.

    Approach (documented):
      1. Call securityhub:ListStandardsSubscriptions to get all enabled standards.
         API response field: StandardsSubscriptions[].StandardsSubscriptionArn
      2. For each subscription, call securityhub:DescribeStandardsControls
         (paginated) to get all controls.
         Fields used per control:
           ControlStatus  ("ENABLED" | "DISABLED")
           ComplianceStatus ("PASSED" | "FAILED" | "NOT_AVAILABLE" | "WARNING")
      3. proxy_score = 100.0 * passed / max(total_enabled, 1)
         where:
           total_enabled = controls where ControlStatus == "ENABLED"
           passed        = enabled controls where ComplianceStatus == "PASSED"

    Note: Security Hub does NOT expose a single numeric "score" endpoint; the
    Security Score shown in the console is computed client-side from the same
    pass/fail data we use here.
    """
    scores = []
    api_calls = 0

    # 1. List all enabled standards
    sub_resp = sh_client.list_standards_subscriptions()
    api_calls += 1
    subscriptions = sub_resp.get("StandardsSubscriptions", [])

    for sub in subscriptions:
        arn   = sub["StandardsSubscriptionArn"]
        name  = sub.get("StandardsArn", arn).split("/")[-1]
        status = sub.get("StandardsStatus", "READY")

        if status != "READY":
            # Standard is still being enabled; skip to avoid incomplete data
            scores.append(dict(
                standard_arn=sub.get("StandardsArn", arn),
                subscription_arn=arn,
                status=status,
                total_enabled_controls=0,
                passed_controls=0,
                failed_controls=0,
                proxy_score=None,
                note="Standard not yet READY",
            ))
            continue

        total_enabled = 0
        passed        = 0
        failed        = 0

        # 2. Paginate controls for this standard
        next_token = None
        while True:
            params = dict(StandardsSubscriptionArn=arn, MaxResults=100)
            if next_token:
                params["NextToken"] = next_token
            ctrl_resp = sh_client.describe_standards_controls(**params)
            api_calls += 1

            for ctrl in ctrl_resp.get("Controls", []):
                if ctrl.get("ControlStatus") != "ENABLED":
                    continue  # skip disabled controls
                total_enabled += 1
                cs = ctrl.get("ComplianceStatus", "")
                if cs == "PASSED":
                    passed += 1
                elif cs in ("FAILED", "WARNING"):
                    failed += 1
                # NOT_AVAILABLE / empty → neither passed nor failed

            next_token = ctrl_resp.get("NextToken")
            if not next_token:
                break

        proxy_score = round(100.0 * passed / max(total_enabled, 1), 2)

        scores.append(dict(
            standard_arn=sub.get("StandardsArn", arn),
            subscription_arn=arn,
            status=status,
            total_enabled_controls=total_enabled,
            passed_controls=passed,
            failed_controls=failed,
            proxy_score=proxy_score,
        ))

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "collect_standards_scores",
        "standards_evaluated": len(scores),
        "api_calls": api_calls,
    }))

    return scores, api_calls


# ---------------------------------------------------------------------------
# Report builders
# ---------------------------------------------------------------------------

def _top_n(counter_dict, n=10):
    """Return sorted list of (key, count) tuples, descending by count."""
    return sorted(counter_dict.items(), key=lambda kv: kv[1], reverse=True)[:n]


def _build_exec_summary(report_date_str, cfg, s3_prefix, agg, nr, standards):
    """Build the executive_summary.md text."""
    sev = agg["severity_counts"]
    wf  = agg["workflow_counts"]
    top_ctrl = _top_n(agg["control_counts"], 10)
    top_res  = _top_n(agg["resource_type_counts"], 10)

    lines = [
        f"# AWS Security Hub – Daily Posture Report",
        f"**Report Date (UTC):** {report_date_str}",
        f"**S3 Output:** s3://{cfg['bucket']}/{s3_prefix}",
        f"**Lookback Window:** {cfg['lookback_hours']} hours",
        "",
        "---",
        "",
        "## Overall Findings",
        f"- **Total active findings:** {agg['total']:,}",
        "",
        "### By Severity",
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
            arn_short = s["standard_arn"].split("/")[-1]
            lines.append(
                f"- **{arn_short}**: {score_str} "
                f"({s['passed_controls']} passed / {s['total_enabled_controls']} enabled controls)"
            )
    else:
        lines.append("- No standards data available.")

    lines += ["", "---", "", "## Recent Activity"]
    lines.append(f"- **New findings (last {nr['lookback_hours']}h):** {nr['new_count']:,}")
    lines.append(f"- **Resolved findings (last {nr['lookback_hours']}h):** {nr['resolved_count']:,}")

    lines += ["", "---", "", "## Top 10 Failing Controls"]
    lines.append("| Control ID / Generator | Title | Count |")
    lines.append("|---|---|---|")
    for key, cnt in top_ctrl:
        parts = key.split("|||", 1)
        ctrl_id    = parts[0]
        ctrl_title = parts[1] if len(parts) > 1 else ""
        lines.append(f"| {ctrl_id} | {ctrl_title[:80]} | {cnt:,} |")

    lines += ["", "---", "", "## Top 10 Resource Types"]
    lines.append("| Resource Type | Count |")
    lines.append("|---|---|")
    for rtype, cnt in top_res:
        lines.append(f"| {rtype} | {cnt:,} |")

    lines += ["", "---", f"*Generated by Security Hub Daily Posture Lambda – {_iso(_utc_now())}*"]

    return "\n".join(lines) + "\n"


def _build_sns_message(report_date_str, cfg, s3_prefix, agg, nr, standards):
    """Build the plain-text SNS message body."""
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
            arn_short = s["standard_arn"].split("/")[-1]
            lines.append(
                f"  {arn_short}: {score_str} "
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

    lines += ["", "=" * 60, "Generated by Security Hub Daily Posture Lambda"]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SNS publish
# ---------------------------------------------------------------------------

def _publish_sns(sns_client, topic_arn, subject, message, dry_run=False):
    if dry_run:
        print(json.dumps({
            "level": "INFO",
            "dry_run": True,
            "would_publish_sns": True,
            "subject": subject,
            "message_preview": message[:500],
        }))
        return False

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],  # SNS subject max 100 chars
        Message=message,
    )
    return True


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event, context):
    execution_id = getattr(context, "aws_request_id", str(uuid.uuid4()))
    start_time   = time.time()

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "start",
        "event": event,
    }))

    # ------------------------------------------------------------------
    # Resolve configuration
    # ------------------------------------------------------------------
    cfg = _cfg()

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "config_resolved",
        "bucket": cfg["bucket"],
        "prefix": cfg["prefix"],
        "region": cfg["region"],
        "lookback_hours": cfg["lookback_hours"],
        "sns_topic_arn": cfg["topic_arn"] or "DISABLED",
        "dry_run": cfg["dry_run"],
    }))

    # ------------------------------------------------------------------
    # boto3 clients
    # ------------------------------------------------------------------
    sh_client  = boto3.client("securityhub", region_name=cfg["region"])
    s3_client  = boto3.client("s3")
    sns_client = boto3.client("sns", region_name=cfg["region"])

    # ------------------------------------------------------------------
    # Timestamps & partition
    # ------------------------------------------------------------------
    now            = _utc_now()
    report_date    = now.strftime("%Y-%m-%d")
    s3_date_prefix = _date_partition_prefix(cfg, now)

    # ------------------------------------------------------------------
    # Collect data
    # ------------------------------------------------------------------
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
            account_region_counts={}, resource_type_counts={}, control_counts={}, api_calls=0,
        )

    # 2. New / resolved in lookback window
    try:
        nr = _collect_new_resolved(sh_client, cfg, execution_id)
    except Exception as exc:
        err = {"step": "collect_new_resolved", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        nr = dict(
            lookback_hours=cfg["lookback_hours"],
            cutoff_utc="",
            new_count=0,
            resolved_count=0,
            api_calls=0,
        )

    # 3. Standards scores
    try:
        standards, std_api_calls = _collect_standards_scores(sh_client, execution_id)
    except Exception as exc:
        err = {"step": "collect_standards_scores", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
        standards      = []
        std_api_calls  = 0

    # ------------------------------------------------------------------
    # Derive top-N lists
    # ------------------------------------------------------------------
    top_controls      = _top_n(agg["control_counts"], 10)
    top_resource_types = _top_n(agg["resource_type_counts"], 10)

    # ------------------------------------------------------------------
    # Build full report JSON
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

    # ------------------------------------------------------------------
    # Build executive summary markdown
    # ------------------------------------------------------------------
    exec_summary = _build_exec_summary(report_date, cfg, s3_date_prefix, agg, nr, standards)

    # ------------------------------------------------------------------
    # Build CSVs
    # ------------------------------------------------------------------

    # findings_by_severity.csv
    csv_severity = _csv_from_rows(
        ["severity", "count"],
        sorted(agg["severity_counts"].items()),
    )

    # findings_by_workflow.csv
    csv_workflow = _csv_from_rows(
        ["workflow_status", "count"],
        sorted(agg["workflow_counts"].items()),
    )

    # findings_by_product.csv
    csv_product = _csv_from_rows(
        ["product_name", "count"],
        sorted(agg["product_counts"].items(), key=lambda x: x[1], reverse=True),
    )

    # findings_by_account_region.csv
    acct_reg_rows = []
    for key, cnt in sorted(agg["account_region_counts"].items(), key=lambda x: x[1], reverse=True):
        parts = key.split("|", 1)
        acct  = parts[0]
        reg   = parts[1] if len(parts) > 1 else ""
        acct_reg_rows.append([acct, reg, cnt])
    csv_account_region = _csv_from_rows(["account_id", "region", "count"], acct_reg_rows)

    # top_failing_controls.csv
    ctrl_rows = []
    for key, cnt in top_controls:
        parts      = key.split("|||", 1)
        ctrl_id    = parts[0]
        ctrl_title = parts[1] if len(parts) > 1 else ""
        ctrl_rows.append([ctrl_id, ctrl_title, cnt])
    csv_controls = _csv_from_rows(["control_id", "title", "count"], ctrl_rows)

    # top_resource_types.csv
    csv_resource_types = _csv_from_rows(
        ["resource_type", "count"],
        [[rt, cnt] for rt, cnt in top_resource_types],
    )

    # new_last_{n}h.csv
    csv_new = _csv_from_rows(
        ["metric", "value"],
        [
            ["lookback_hours", nr["lookback_hours"]],
            ["cutoff_utc",     nr["cutoff_utc"]],
            ["new_findings",   nr["new_count"]],
        ],
    )

    # resolved_last_{n}h.csv
    csv_resolved = _csv_from_rows(
        ["metric", "value"],
        [
            ["lookback_hours",     nr["lookback_hours"]],
            ["cutoff_utc",         nr["cutoff_utc"]],
            ["resolved_findings",  nr["resolved_count"]],
        ],
    )

    # ------------------------------------------------------------------
    # Write all files to S3
    # ------------------------------------------------------------------
    files_to_write = [
        ("report.json",
         json.dumps(report, indent=2, default=str), "application/json"),
        ("executive_summary.md",
         exec_summary, "text/markdown"),
        ("findings_by_severity.csv",
         csv_severity, "text/csv"),
        ("findings_by_workflow.csv",
         csv_workflow, "text/csv"),
        ("findings_by_product.csv",
         csv_product, "text/csv"),
        ("findings_by_account_region.csv",
         csv_account_region, "text/csv"),
        ("top_failing_controls.csv",
         csv_controls, "text/csv"),
        ("top_resource_types.csv",
         csv_resource_types, "text/csv"),
        (f"new_last_{cfg['lookback_hours']}h.csv",
         csv_new, "text/csv"),
        (f"resolved_last_{cfg['lookback_hours']}h.csv",
         csv_resolved, "text/csv"),
    ]

    written_keys = []
    for filename, content, ctype in files_to_write:
        key = s3_date_prefix + filename
        try:
            _write_s3_bytes(
                s3_client,
                cfg["bucket"],
                key,
                content.encode("utf-8"),
                content_type=ctype,
                dry_run=cfg["dry_run"],
            )
            written_keys.append(key)
        except Exception as exc:
            err = {"step": "write_s3", "key": key, "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "s3_writes_complete",
        "files_written": len(written_keys),
        "dry_run": cfg["dry_run"],
    }))

    # ------------------------------------------------------------------
    # Publish SNS
    # ------------------------------------------------------------------
    sns_published = False
    if cfg["topic_arn"]:
        subject     = f"Security Hub Daily Posture Report – {report_date}"
        sns_message = _build_sns_message(report_date, cfg, s3_date_prefix, agg, nr, standards)
        try:
            sns_published = _publish_sns(
                sns_client,
                cfg["topic_arn"],
                subject,
                sns_message,
                dry_run=cfg["dry_run"],
            )
            print(json.dumps({
                "level": "INFO",
                "execution_id": execution_id,
                "step": "sns_publish",
                "published": sns_published,
                "dry_run": cfg["dry_run"],
            }))
        except Exception as exc:
            err = {"step": "sns_publish", "error": str(exc)}
            errors.append(err)
            print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))
    else:
        print(json.dumps({
            "level": "INFO",
            "execution_id": execution_id,
            "step": "sns_publish",
            "skipped": True,
            "reason": "SNS_TOPIC_ARN not configured",
        }))

    # ------------------------------------------------------------------
    # Final structured log
    # ------------------------------------------------------------------
    elapsed = round(time.time() - start_time, 3)
    print(json.dumps({
        "level": "INFO",
        "execution_id": execution_id,
        "step": "complete",
        "elapsed_seconds": elapsed,
        "total_findings": agg["total"],
        "new_count": nr["new_count"],
        "resolved_count": nr["resolved_count"],
        "standards_evaluated": len(standards),
        "files_written": len(written_keys),
        "sns_published": sns_published,
        "errors": len(errors),
    }))

    # ------------------------------------------------------------------
    # Return value
    # ------------------------------------------------------------------
    return {
        "report_date":                report_date,
        "s3_bucket":                  cfg["bucket"],
        "s3_prefix_written":          s3_date_prefix,
        "totals": {
            "overall":     agg["total"],
            "by_severity": agg["severity_counts"],
            "by_workflow": agg["workflow_counts"],
        },
        "top_controls": [
            {"control_id": k.split("|||")[0], "title": k.split("|||")[1] if "|||" in k else "", "count": v}
            for k, v in top_controls
        ],
        "top_resource_types": [
            {"type": rt, "count": cnt} for rt, cnt in top_resource_types
        ],
        "new_count_last_lookback":      nr["new_count"],
        "resolved_count_last_lookback": nr["resolved_count"],
        "sns_published":               sns_published,
        "errors":                      errors,
    }
