#!/usr/bin/env python3
"""Records a scan unit's result in Postgres, publishes the per-unit result
message, and — if this is the last unit for the scan — publishes the
aggregate scan.completed event exactly once via an atomic counter increment.
"""
import argparse
import json
import os
from datetime import datetime, timezone

import pika
import psycopg2


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--scan-id", required=True)
    p.add_argument("--project-path", required=True)
    p.add_argument("--scan-type", required=True)
    p.add_argument("--status", required=True)
    p.add_argument("--object-key", default="")
    p.add_argument("--summary", default="{}")
    p.add_argument("--cli-version", default="")
    return p.parse_args()


def publish(channel, queue: str, payload: dict):
    channel.basic_publish(
        exchange="",
        routing_key=queue,
        body=json.dumps(payload),
        properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
    )


def main():
    args = parse_args()
    summary = json.loads(args.summary)
    now = datetime.now(timezone.utc).isoformat()

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_units
            SET status = %s, object_key = %s, vuln_summary = %s,
                snyk_cli_version = %s, finished_at = %s
            WHERE scan_id = %s AND project_path = %s AND scan_type = %s
            """,
            (args.status, args.object_key, json.dumps(summary), args.cli_version,
             now, args.scan_id, args.project_path, args.scan_type),
        )
    conn.commit()

    params = pika.URLParameters(os.environ["RABBITMQ_URL"])
    connection = pika.BlockingConnection(params)
    channel = connection.channel()

    publish(channel, os.environ.get("RESULT_QUEUE", "scan.results"), {
        "scan_id": args.scan_id,
        "project_path": args.project_path,
        "scan_type": args.scan_type,
        "status": args.status,
        "object_key": args.object_key,
        "summary": summary,
    })

    # This UPDATE...RETURNING is the synchronization point: every scan unit
    # job that finishes increments completed_units, and whichever one's
    # increment makes completed_units == expected_units is the single job
    # responsible for publishing scan.completed. Postgres row-level locking
    # makes this exactly-once without a separate coordinator process.
    is_last = False
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scans SET completed_units = completed_units + 1
            WHERE scan_id = %s
            RETURNING completed_units, expected_units
            """,
            (args.scan_id,),
        )
        completed_units, expected_units = cur.fetchone()
        is_last = completed_units >= expected_units
        if is_last:
            cur.execute(
                "UPDATE scans SET status = 'completed', completed_at = %s WHERE scan_id = %s",
                (now, args.scan_id),
            )
    conn.commit()

    if is_last:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT scan_type, vuln_summary FROM scan_units
                WHERE scan_id = %s AND vuln_summary IS NOT NULL
                """,
                (args.scan_id,),
            )
            rows = cur.fetchall()
            cur.execute("SELECT git_url, ref FROM scans WHERE scan_id = %s", (args.scan_id,))
            git_url, ref = cur.fetchone()

        overall = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for _scan_type, vs in rows:
            for sev, count in (vs or {}).items():
                if sev in overall:
                    overall[sev] += count

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET overall_summary = %s WHERE scan_id = %s",
                (json.dumps(overall), args.scan_id),
            )
        conn.commit()

        publish(channel, os.environ.get("COMPLETION_QUEUE", "scan.completed"), {
            "event": "scan.completed",
            "scan_id": args.scan_id,
            "git_url": git_url,
            "ref": ref,
            "overall_summary": overall,
        })

    connection.close()
    conn.close()


if __name__ == "__main__":
    main()
