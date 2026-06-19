import psycopg2
import psycopg2.extras

from config import Config


def get_conn():
    return psycopg2.connect(Config.DATABASE_URL)


def create_scan(conn, scan_id: str, git_url: str, ref: str, org_id: str | None, expected_units: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (scan_id, git_url, ref, org_id, status, expected_units)
            VALUES (%s, %s, %s, %s, 'in_progress', %s)
            ON CONFLICT (scan_id) DO NOTHING
            """,
            (scan_id, git_url, ref, org_id, expected_units),
        )
    conn.commit()


def scan_exists(conn, scan_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM scans WHERE scan_id = %s", (scan_id,))
        return cur.fetchone() is not None


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
