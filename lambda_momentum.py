"""
AWS Security Hub Weekly Momentum Reporter – Lambda Function
Python 3.12 + boto3

PURPOSE
-------
Answers one question: "Are we winning or losing?"

  Momentum = total resolved this week  −  total new this week
    positive → resolving faster than findings appear  (improving)
    negative → falling behind                         (action required)

Reads the compact posture-snapshot JSONs written by lambda_function.py
(s3://<bucket>/<prefix>posture-snapshots/YYYY-MM-DD.json) and publishes
a Monday morning report with the current week's momentum plus a 4-week
trend.  Also writes the weekly result to S3 so future runs can display
the trend.

USAGE
-----
1. Paste this file into a new Lambda function in the console.
2. Edit the CONFIG section below (or set the corresponding env-vars).
3. Attach an IAM role with:
     s3:GetObject   (on <bucket>/<prefix>posture-snapshots/* and posture-momentum/*)
     s3:PutObject   (on <bucket>/<prefix>posture-momentum/*)
     sns:Publish    (on the destination topic)
4. Schedule via EventBridge cron:  cron(0 8 ? * MON *)   (Monday 08:00 UTC)

DATA FLOW
---------
  lambda_function.py  →  writes  s3://<bucket>/<prefix>posture-snapshots/YYYY-MM-DD.json
  lambda_momentum.py  →  reads   last 7 daily snapshots
                      →  writes  s3://<bucket>/<prefix>posture-momentum/YYYY-WNN.json
                      →  reads   up to 3 prior weekly records for trend
                      →  publishes SNS report
"""

# ============================================================
# CONFIG  –  edit these values or override via env-vars
# ============================================================
S3_BUCKET      = "variable"       # REPORT_BUCKET env-var overrides  (must match lambda_function.py)
S3_PREFIX      = "variable/"      # REPORT_PREFIX env-var overrides  (must match lambda_function.py)
SNS_TOPIC_ARN  = "variable"       # SNS_TOPIC_ARN env-var overrides
REGION         = "us-gov-west-1"  # SECURITY_HUB_REGION env-var overrides
TREND_WEEKS    = 4                # TREND_WEEKS env-var overrides – how many weeks to display
DRY_RUN        = False
# ============================================================

import json
import os
import time
import uuid
from datetime import datetime, timezone, timedelta

import boto3


# ---------------------------------------------------------------------------
# Helpers – configuration
# ---------------------------------------------------------------------------

def _cfg():
    def _env_bool(name, default):
        v = os.environ.get(name, "").strip().lower()
        return True if v in ("1", "true", "yes") else (False if v in ("0", "false", "no") else default)

    bucket      = os.environ.get("REPORT_BUCKET",       S3_BUCKET).strip()
    prefix      = os.environ.get("REPORT_PREFIX",       S3_PREFIX).strip()
    topic_arn   = os.environ.get("SNS_TOPIC_ARN",       SNS_TOPIC_ARN or "").strip()
    region      = os.environ.get("SECURITY_HUB_REGION", REGION or os.environ.get("AWS_REGION", "us-east-1")).strip()
    trend_weeks = int(os.environ.get("TREND_WEEKS",     str(TREND_WEEKS)))
    dry_run     = _env_bool("DRY_RUN", DRY_RUN)

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    return dict(
        bucket=bucket,
        prefix=prefix,
        topic_arn=topic_arn if topic_arn else None,
        region=region,
        trend_weeks=trend_weeks,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Helpers – time
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(tz=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_week_label(dt):
    """Return a string like '2026-W10' for a given datetime."""
    iso = dt.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def _last_n_dates(n, from_dt=None):
    """Return list of 'YYYY-MM-DD' strings for the last n calendar days (newest first)."""
    base = from_dt or _utc_now()
    return [(base - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n)]


# ---------------------------------------------------------------------------
# Helpers – S3 read/write  (mirrors lambda_function.py patterns)
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


def _load_daily_snapshots(s3_client, cfg, dates, execution_id):
    """
    Try to load a posture-snapshot for each date in *dates*.
    Missing snapshots (Lambda gaps, first deployment) are silently skipped.
    Returns list of loaded snapshot dicts.
    """
    snapshots = []
    for date_str in dates:
        key = f"{cfg['prefix']}posture-snapshots/{date_str}.json"
        data = _s3_get_json(s3_client, cfg["bucket"], key)
        if data:
            snapshots.append(data)

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "load_daily_snapshots",
        "requested": len(dates), "loaded": len(snapshots),
    }))
    return snapshots


def _load_weekly_records(s3_client, cfg, week_labels, execution_id):
    """Load prior weekly momentum records from S3. Missing weeks are skipped."""
    records = []
    for label in week_labels:
        key = f"{cfg['prefix']}posture-momentum/{label}.json"
        data = _s3_get_json(s3_client, cfg["bucket"], key)
        if data:
            records.append(data)
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "load_weekly_records",
        "requested": len(week_labels), "loaded": len(records),
    }))
    return records


def _save_weekly_record(s3_client, cfg, week_label, record, execution_id):
    key = f"{cfg['prefix']}posture-momentum/{week_label}.json"
    _write_s3_bytes(
        s3_client, cfg["bucket"], key,
        json.dumps(record, indent=2).encode("utf-8"),
        content_type="application/json",
        dry_run=cfg["dry_run"],
    )
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "save_weekly_record",
        "s3_uri": f"s3://{cfg['bucket']}/{key}",
    }))


# ---------------------------------------------------------------------------
# Momentum computation
# ---------------------------------------------------------------------------

def _compute_momentum(snapshots):
    """Sum new/resolved across all snapshots and return the momentum score."""
    total_new      = sum(s.get("new_count", 0) for s in snapshots)
    total_resolved = sum(s.get("resolved_count", 0) for s in snapshots)
    return dict(
        total_new=total_new,
        total_resolved=total_resolved,
        momentum=total_resolved - total_new,
        snapshot_count=len(snapshots),
    )


def _momentum_label(score):
    if score > 10:
        return "IMPROVING"
    if score >= 0:
        return "STABLE"
    if score >= -10:
        return "SLIPPING"
    return "WORSENING"


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
# Report builder
# ---------------------------------------------------------------------------

def _build_report(report_date, week_label, this_week, prior_weeks, snapshots):
    """
    Build the weekly momentum plain-text SNS message.

    Example:
    ================================================================
    Security Hub Weekly Momentum Report – 2026-W10 (2026-03-09)
    ================================================================
    Momentum Score : +23   (52 resolved − 29 new this week)
    Interpretation : IMPROVING — resolving faster than findings appear

    4-WEEK TREND
      2026-W07 (2026-02-16):  −14  [WORSENING]
      2026-W08 (2026-02-23):   +3  [STABLE]
      2026-W09 (2026-03-02):  +18  [IMPROVING]
      2026-W10 (2026-03-09):  +23  [IMPROVING]  ← this week
    ================================================================
    Based on 7 daily snapshots  (2026-03-03 to 2026-03-09)
    """
    momentum   = this_week["momentum"]
    m_label    = _momentum_label(momentum)
    m_resolved = this_week["total_resolved"]
    m_new      = this_week["total_new"]

    if momentum > 0:
        interpretation = f"{m_label} — resolving faster than findings appear"
    elif momentum == 0:
        interpretation = f"{m_label} — exactly keeping pace with new findings"
    else:
        interpretation = f"{m_label} — new findings outpacing remediation"

    all_weeks = list(prior_weeks) + [{
        "week_label":  week_label,
        "report_date": report_date,
        "momentum":    momentum,
        "label":       m_label,
        "is_current":  True,
    }]

    snap_dates = [s.get("date", "?") for s in snapshots]
    date_range = (
        f"{min(snap_dates)} to {max(snap_dates)}" if snap_dates else "no snapshots"
    )

    lines = [
        f"Security Hub Weekly Momentum Report – {week_label} ({report_date})",
        "=" * 64,
        f"Momentum Score : {momentum:+d}   ({m_resolved} resolved − {m_new} new this week)",
        f"Interpretation : {interpretation}",
        "",
        f"{len(all_weeks)}-WEEK TREND",
    ]
    for w in all_weeks:
        w_momentum = w.get("momentum", 0)
        w_label    = w.get("label") or _momentum_label(w_momentum)
        w_week     = w.get("week_label", "?")
        w_date     = w.get("report_date", "")
        date_part  = f" ({w_date})" if w_date else ""
        current    = "  ← this week" if w.get("is_current") else ""
        lines.append(f"  {w_week}{date_part}: {w_momentum:+5d}  [{w_label}]{current}")

    lines += [
        "=" * 64,
        f"Based on {this_week['snapshot_count']} daily snapshots  ({date_range})",
        f"Generated: {_iso(_utc_now())}",
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

    if not cfg["bucket"]:
        raise RuntimeError("REPORT_BUCKET env-var is required for lambda_momentum.")
    if not cfg["topic_arn"]:
        raise RuntimeError("SNS_TOPIC_ARN env-var is required for lambda_momentum.")

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "config_resolved",
        "bucket": cfg["bucket"], "prefix": cfg["prefix"],
        "region": cfg["region"], "trend_weeks": cfg["trend_weeks"],
        "dry_run": cfg["dry_run"],
    }))

    s3_client  = boto3.client("s3")
    sns_client = boto3.client("sns", region_name=cfg["region"])

    now         = _utc_now()
    report_date = now.strftime("%Y-%m-%d")
    week_label  = _iso_week_label(now)

    # Load last 7 daily snapshots
    last_7_dates = _last_n_dates(7, now)
    snapshots    = _load_daily_snapshots(s3_client, cfg, last_7_dates, execution_id)

    if not snapshots:
        print(json.dumps({
            "level": "WARNING", "execution_id": execution_id,
            "message": (
                "No daily snapshots found in the last 7 days. "
                "Ensure lambda_function.py has S3_BUCKET / REPORT_BUCKET configured "
                "and the REPORT_PREFIX values match."
            ),
        }))

    # Compute this week's momentum
    this_week = _compute_momentum(snapshots)
    this_week.update({
        "week_label":  week_label,
        "report_date": report_date,
        "label":       _momentum_label(this_week["momentum"]),
    })

    # Load prior (TREND_WEEKS − 1) weekly records for the trend table
    prior_week_labels = []
    for i in range(1, cfg["trend_weeks"]):
        prior_week_labels.append(_iso_week_label(now - timedelta(weeks=i)))
    prior_week_labels.reverse()  # chronological order, oldest first

    prior_weeks = _load_weekly_records(s3_client, cfg, prior_week_labels, execution_id)

    # Save this week's record (idempotent – safe to overwrite if re-run)
    errors = []
    try:
        _save_weekly_record(s3_client, cfg, week_label, this_week, execution_id)
    except Exception as exc:
        err = {"step": "save_weekly_record", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    # Build and publish report
    report_body = _build_report(report_date, week_label, this_week, prior_weeks, snapshots)

    if errors:
        report_body += "\n\nERRORS:\n" + "".join(f"  - {e['step']}: {e['error']}\n" for e in errors)

    sns_published = False
    try:
        sns_published = _publish_sns(
            sns_client, cfg["topic_arn"],
            f"Security Hub Momentum Report – {week_label} ({report_date})",
            report_body,
            dry_run=cfg["dry_run"],
        )
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "sns_publish", "published": sns_published,
        }))
    except Exception as exc:
        err = {"step": "sns_publish", "error": str(exc)}
        errors.append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    elapsed = round(time.time() - start_time, 3)
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "complete", "elapsed_seconds": elapsed,
        "week_label": week_label,
        "momentum": this_week["momentum"],
        "sns_published": sns_published,
        "errors": len(errors),
    }))

    return {
        "report_date":    report_date,
        "week_label":     week_label,
        "momentum":       this_week["momentum"],
        "total_new":      this_week["total_new"],
        "total_resolved": this_week["total_resolved"],
        "sns_published":  sns_published,
        "errors":         errors,
    }
