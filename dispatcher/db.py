import psycopg2
import psycopg2.extras

from config import Config


def get_conn():
    return psycopg2.connect(Config.DATABASE_URL)


def create_scan(conn, scan_id: str, git_url: str, ref: str, org_id: str | None, expected_units: int) -> None:
    """Insert or update the scan row when the dispatcher takes ownership.

    The API may have pre-created the row with status='pending'. The upsert
    transitions it to 'in_progress' and sets expected_units.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (scan_id, git_url, ref, org_id, status, expected_units)
            VALUES (%s, %s, %s, %s, 'in_progress', %s)
            ON CONFLICT (scan_id) DO UPDATE
                SET status = 'in_progress',
                    expected_units = EXCLUDED.expected_units
            """,
            (scan_id, git_url, ref, org_id, expected_units),
        )
    conn.commit()


def scan_already_dispatched(conn, scan_id: str) -> bool:
    """Return True if the scan exists and is past the pending state.

    A 'pending' row was created by the API and is still waiting for the
    dispatcher — it must NOT be treated as a duplicate.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM scans WHERE scan_id = %s AND status != 'pending'",
            (scan_id,),
        )
        return cur.fetchone() is not None


def get_scan(conn, scan_id: str) -> dict | None:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT scan_id, git_url, ref, commit_sha, status, error
            FROM scans WHERE scan_id = %s
            """,
            (scan_id,),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def set_scan_commit_sha(conn, scan_id: str, commit_sha: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scans SET commit_sha = %s WHERE scan_id = %s",
            (commit_sha, scan_id),
        )
    conn.commit()


def upsert_scan_unit_pending(conn, scan_id: str, project_path: str, scan_type: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_units (scan_id, project_path, scan_type, status)
            VALUES (%s, %s, %s, 'pending')
            ON CONFLICT (scan_id, project_path, scan_type) DO NOTHING
            """,
            (scan_id, project_path, scan_type),
        )
    conn.commit()
