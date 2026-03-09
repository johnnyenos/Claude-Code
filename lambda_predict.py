"""
AWS Security Hub Posture Threshold Predictor – Lambda Function
Python 3.12 + boto3

PURPOSE
-------
Reads 30 days of daily posture-score snapshots from S3, fits a linear
trend using pure Python (no numpy / scipy), and projects when the
composite score will fall below a configurable threshold.

Sends an SNS alert only when a breach is predicted within WARN_DAYS
(default 14).  Runs silently when posture is healthy or data is sparse.

USAGE
-----
1. Paste this file into a new Lambda function in the console.
2. Edit the CONFIG section below (or set the corresponding env-vars).
3. Attach an IAM role with:
     s3:GetObject   (on <bucket>/<prefix>posture-snapshots/*)
     sns:Publish    (on the destination topic)
4. Schedule via EventBridge (same daily cron as lambda_function.py).
   The Lambda only sends email when a breach is actually predicted.

DATA FLOW
---------
  lambda_function.py  →  writes  s3://<bucket>/<prefix>posture-snapshots/YYYY-MM-DD.json
  lambda_predict.py   →  reads   last LOOKBACK_DAYS snapshots
                      →  fits linear trend  (pure Python least-squares)
                      →  if breach within WARN_DAYS → sns:Publish alert
"""

# ============================================================
# CONFIG  –  edit these values or override via env-vars
# ============================================================
S3_BUCKET        = "variable"       # REPORT_BUCKET env-var overrides  (must match lambda_function.py)
S3_PREFIX        = "variable/"      # REPORT_PREFIX env-var overrides  (must match lambda_function.py)
SNS_TOPIC_ARN    = "variable"       # SNS_TOPIC_ARN env-var overrides
REGION           = "us-gov-west-1"  # SECURITY_HUB_REGION env-var overrides
SCORE_THRESHOLD  = 70.0             # SCORE_THRESHOLD env-var – alert when score projected below this
WARN_DAYS        = 14               # WARN_DAYS env-var – alert if breach within this many days
LOOKBACK_DAYS    = 30               # LOOKBACK_DAYS env-var – days of history to load
MIN_DATA_POINTS  = 5                # Minimum snapshots required before making a prediction
DRY_RUN          = False
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

    bucket    = os.environ.get("REPORT_BUCKET",       S3_BUCKET).strip()
    prefix    = os.environ.get("REPORT_PREFIX",       S3_PREFIX).strip()
    topic_arn = os.environ.get("SNS_TOPIC_ARN",       SNS_TOPIC_ARN or "").strip()
    region    = os.environ.get("SECURITY_HUB_REGION", REGION or os.environ.get("AWS_REGION", "us-east-1")).strip()
    threshold = float(os.environ.get("SCORE_THRESHOLD", str(SCORE_THRESHOLD)))
    warn_days = int(os.environ.get("WARN_DAYS",        str(WARN_DAYS)))
    lookback  = int(os.environ.get("LOOKBACK_DAYS",    str(LOOKBACK_DAYS)))
    dry_run   = _env_bool("DRY_RUN", DRY_RUN)

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    return dict(
        bucket=bucket,
        prefix=prefix,
        topic_arn=topic_arn if topic_arn else None,
        region=region,
        threshold=threshold,
        warn_days=warn_days,
        lookback_days=lookback,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Helpers – time
# ---------------------------------------------------------------------------

def _utc_now():
    return datetime.now(tz=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _last_n_dates(n, from_dt=None):
    """Return list of 'YYYY-MM-DD' strings for the last n calendar days (newest first)."""
    base = from_dt or _utc_now()
    return [(base - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n)]


# ---------------------------------------------------------------------------
# Helpers – S3 read  (mirrors lambda_function.py patterns)
# ---------------------------------------------------------------------------

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


def _load_snapshots(s3_client, cfg, dates, execution_id):
    """
    Load posture snapshots for the given dates.
    Only returns snapshots that have a composite_posture_score.
    Missing dates are silently skipped.
    Returns list ordered newest-first.
    """
    snapshots = []
    for date_str in dates:
        key  = f"{cfg['prefix']}posture-snapshots/{date_str}.json"
        data = _s3_get_json(s3_client, cfg["bucket"], key)
        if data and data.get("composite_posture_score") is not None:
            snapshots.append(data)

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "load_snapshots",
        "requested": len(dates), "usable": len(snapshots),
    }))
    return snapshots  # newest first


# ---------------------------------------------------------------------------
# Pure-Python linear regression (no external dependencies)
# ---------------------------------------------------------------------------

def _linear_regression(xs, ys):
    """
    Ordinary least-squares linear regression.
    Returns (slope, intercept) for  y = slope * x + intercept.
    Uses only standard Python floats — no numpy, no scipy.
    """
    n      = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num    = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den    = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return 0.0, mean_y          # perfectly flat line
    slope     = num / den
    intercept = mean_y - slope * mean_x
    return slope, intercept


def _project_breach(slope, intercept, current_x, threshold):
    """
    Return the number of days from today until the regression line crosses
    *threshold*, or None if the trend is flat or improving.

    If the score is already at or below threshold, returns 0.
    """
    if slope >= 0:
        return None                 # score is flat or rising — no breach
    y_current = intercept + slope * current_x
    if y_current <= threshold:
        return 0                    # already at or below threshold
    return (threshold - y_current) / slope   # positive days-until value


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
# Alert builder
# ---------------------------------------------------------------------------

def _build_alert(cfg, snapshots, slope, intercept, days_until, report_date):
    """Build the plain-text SNS alert message."""
    n             = len(snapshots)
    newest        = snapshots[0]   # newest-first list
    oldest        = snapshots[-1]
    current_score = newest.get("composite_posture_score", 0.0)
    breach_date   = (_utc_now() + timedelta(days=days_until)).strftime("%Y-%m-%d")
    rate_str      = f"{slope:+.2f} points/day"

    lines = [
        "SECURITY HUB POSTURE ALERT – Threshold Breach Predicted",
        "=" * 60,
        f"Current Score   : {current_score:.1f}%",
        f"Target Threshold: {cfg['threshold']:.1f}%",
        f"Trend ({n} days) : {rate_str}",
        f"Projected Breach: {breach_date}  (in ~{int(days_until)} days)",
        f"Warning Window  : {cfg['warn_days']} days",
        "",
        "ACTION REQUIRED",
        f"  At the current rate ({rate_str}), your security posture",
        f"  score will fall below {cfg['threshold']:.1f}% in approximately",
        f"  {int(days_until)} days (around {breach_date}).",
        "",
        "  Review open HIGH / CRITICAL findings and prioritise remediation",
        "  to reverse the trend before the threshold is breached.",
        "=" * 60,
        f"Data range  : {oldest['date']} to {newest['date']}  ({n} snapshots)",
        f"Generated   : {_iso(_utc_now())}",
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
        raise RuntimeError("REPORT_BUCKET env-var is required for lambda_predict.")
    if not cfg["topic_arn"]:
        raise RuntimeError("SNS_TOPIC_ARN env-var is required for lambda_predict.")

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "config_resolved",
        "bucket": cfg["bucket"], "prefix": cfg["prefix"],
        "threshold": cfg["threshold"],
        "warn_days": cfg["warn_days"],
        "lookback_days": cfg["lookback_days"],
        "dry_run": cfg["dry_run"],
    }))

    s3_client  = boto3.client("s3")
    sns_client = boto3.client("sns", region_name=cfg["region"])

    now         = _utc_now()
    report_date = now.strftime("%Y-%m-%d")

    # Load snapshots (newest first)
    dates     = _last_n_dates(cfg["lookback_days"], now)
    snapshots = _load_snapshots(s3_client, cfg, dates, execution_id)

    result = {
        "report_date":       report_date,
        "snapshots_used":    len(snapshots),
        "alert_sent":        False,
        "days_until_breach": None,
        "errors":            [],
    }

    if len(snapshots) < MIN_DATA_POINTS:
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "insufficient_data",
            "message": (
                f"Only {len(snapshots)} snapshots available; need {MIN_DATA_POINTS}. "
                "No prediction made — will retry when more history accumulates."
            ),
        }))
        return result

    # Regression: x=0 is oldest, x=n-1 is today
    ordered   = list(reversed(snapshots))
    xs        = list(range(len(ordered)))
    ys        = [s["composite_posture_score"] for s in ordered]
    current_x = xs[-1]

    slope, intercept = _linear_regression(xs, ys)
    current_projected = round(intercept + slope * current_x, 2)

    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "regression_complete",
        "slope": round(slope, 4),
        "intercept": round(intercept, 4),
        "current_projected_score": current_projected,
        "threshold": cfg["threshold"],
    }))

    days_until = _project_breach(slope, intercept, current_x, cfg["threshold"])
    result["days_until_breach"] = round(days_until, 1) if days_until is not None else None

    if days_until is None:
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "no_breach_predicted",
            "message": "Trend is flat or improving. No alert sent.",
            "slope": round(slope, 4),
        }))
        return result

    if days_until > cfg["warn_days"]:
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "breach_outside_window",
            "days_until_breach": round(days_until, 1),
            "warn_days": cfg["warn_days"],
            "message": "Breach predicted but outside warning window. No alert sent.",
        }))
        return result

    # Breach predicted within warning window — send alert
    alert_body = _build_alert(cfg, snapshots, slope, intercept, days_until, report_date)
    subject    = (
        f"SECURITY HUB ALERT: Posture breach in ~{int(days_until)}d "
        f"(threshold {cfg['threshold']:.0f}%)"
    )

    try:
        result["alert_sent"] = _publish_sns(
            sns_client, cfg["topic_arn"],
            subject, alert_body,
            dry_run=cfg["dry_run"],
        )
        print(json.dumps({
            "level": "INFO", "execution_id": execution_id,
            "step": "sns_publish",
            "published": result["alert_sent"],
            "days_until_breach": round(days_until, 1),
        }))
    except Exception as exc:
        err = {"step": "sns_publish", "error": str(exc)}
        result["errors"].append(err)
        print(json.dumps({"level": "ERROR", "execution_id": execution_id, **err}))

    elapsed = round(time.time() - start_time, 3)
    print(json.dumps({
        "level": "INFO", "execution_id": execution_id,
        "step": "complete", "elapsed_seconds": elapsed,
        **{k: v for k, v in result.items() if k != "errors"},
        "errors": len(result["errors"]),
    }))

    return result
