"""REST API front-end for the Snyk scanner pipeline.

POST /scan   — accept a scan request, publish to RabbitMQ, return immediately.
GET  /scan   — return the current status of a scan by ?id=<uuid>.

Environment variables required:
  DATABASE_URL       Postgres DSN
  RABBITMQ_URL       amqp:// URL
  ALLOWED_GIT_HOSTS  comma-separated list of permitted git hostnames

Optional:
  REQUEST_QUEUE  defaults to "scan.requests"
"""
import json
import os
import uuid
from urllib.parse import urlparse

import pika
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

app = FastAPI(title="Snyk Scanner API")


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    gitUrl: str
    ref: str = "main"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])


def _assert_host_allowed(git_url: str) -> None:
    """Reject URLs whose hostname is not in ALLOWED_GIT_HOSTS (SSRF guard)."""
    allowed = [h.strip() for h in os.environ.get("ALLOWED_GIT_HOSTS", "").split(",") if h.strip()]
    if not allowed:
        raise ValueError("ALLOWED_GIT_HOSTS is not configured; all scan requests are rejected")

    parsed = urlparse(git_url)
    host = parsed.hostname
    # scp-style git@host:org/repo.git has no scheme; urlparse won't extract hostname
    if host is None and "@" in git_url and ":" in git_url:
        host = git_url.split("@", 1)[1].split(":", 1)[0]

    if not host or host not in allowed:
        raise ValueError(f"git host '{host}' is not in ALLOWED_GIT_HOSTS")


def _row_to_response(row: dict) -> dict:
    """Convert a DB row to the API response shape.

    commitSha is always present (null until the dispatcher fills it in).
    error is omitted entirely when absent.
    """
    result = {
        "id": str(row["scan_id"]),
        "gitUrl": row["git_url"],
        "ref": row["ref"],
        "commitSha": row.get("commit_sha"),
        "status": row["status"],
    }
    if row.get("error"):
        result["error"] = row["error"]
    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/scan", status_code=202)
def create_scan(body: ScanRequest) -> dict:
    """Submit a repo for scanning.

    Creates a 'pending' scan record, publishes to scan.requests, and returns
    immediately. Poll GET /scan?id=<id> for status updates.
    """
    scan_id = str(uuid.uuid4())
    conn = _db_conn()
    try:
        # SSRF guard — reject disallowed hosts before touching the DB
        try:
            _assert_host_allowed(body.gitUrl)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        # Create the pending row so GET works immediately after POST
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (scan_id, git_url, ref, status, expected_units)
                VALUES (%s, %s, %s, 'pending', 0)
                """,
                (scan_id, body.gitUrl, body.ref),
            )
        conn.commit()

        # Publish to RabbitMQ — include scan_id so the dispatcher updates THIS row
        try:
            params = pika.URLParameters(os.environ["RABBITMQ_URL"])
            mq = pika.BlockingConnection(params)
            ch = mq.channel()
            ch.basic_publish(
                exchange="",
                routing_key=os.environ.get("REQUEST_QUEUE", "scan.requests"),
                body=json.dumps({
                    "scan_id": scan_id,
                    "git_url": body.gitUrl,
                    "ref": body.ref,
                }),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type="application/json",
                ),
            )
            mq.close()
        except Exception as exc:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scans SET status = 'failed', error = %s WHERE scan_id = %s",
                    (f"Failed to queue scan: {exc}", scan_id),
                )
            conn.commit()
            return _row_to_response({
                "scan_id": scan_id, "git_url": body.gitUrl, "ref": body.ref,
                "commit_sha": None, "status": "failed",
                "error": f"Failed to queue scan: {exc}",
            })

        return _row_to_response({
            "scan_id": scan_id, "git_url": body.gitUrl, "ref": body.ref,
            "commit_sha": None, "status": "pending",
        })
    finally:
        conn.close()


@app.get("/scan")
def get_scan(id: str = Query(..., description="Scan ID returned by POST /scan")) -> dict:
    """Return the current status of a scan."""
    conn = _db_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT scan_id, git_url, ref, commit_sha, status, error
                FROM scans WHERE scan_id = %s
                """,
                (id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail=f"scan '{id}' not found")
    return _row_to_response(dict(row))
