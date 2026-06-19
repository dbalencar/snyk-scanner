import json
import logging
import uuid

import pika
from kubernetes import client, config as k8s_config

import db
import detector
import git_utils
import k8s_jobs
from config import Config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("dispatcher")


def handle_message(ch, method, properties, body, batch_api, conn):
    try:
        msg = json.loads(body)
    except json.JSONDecodeError:
        log.error("malformed message, routing to DLQ: %s", body[:200])
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        return

    scan_id = msg.get("scan_id") or str(uuid.uuid4())
    git_url = msg["git_url"]
    ref = msg.get("ref", "main")
    org_id = msg.get("org_id")

    if db.scan_exists(conn, scan_id):
        log.info("scan %s already dispatched, skipping (dedup)", scan_id)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return

    clone_path = None
    try:
        clone_path = git_utils.shallow_clone(git_url, ref)
        units = detector.detect(clone_path)

        if not units:
            log.warning("no recognizable project stacks found for scan %s", scan_id)
            db.create_scan(conn, scan_id, git_url, ref, org_id, expected_units=0)
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        db.create_scan(conn, scan_id, git_url, ref, org_id, expected_units=len(units))

        for unit in units:
            for scan_type in unit.scan_types:
                db.upsert_scan_unit_pending(conn, scan_id, unit.project_path, scan_type)

            job = k8s_jobs.build_job(
                scan_id=scan_id,
                git_url=git_url,
                ref=ref,
                image_tag=unit.image_tag,
                project_path=unit.project_path,
                scan_types=sorted(unit.scan_types),
            )
            k8s_jobs.create_job(batch_api, job)
            log.info("dispatched job for scan=%s path=%s types=%s",
                      scan_id, unit.project_path or "<root>", unit.scan_types)

        ch.basic_ack(delivery_tag=method.delivery_tag)

    except git_utils.DisallowedGitHostError as e:
        log.error("rejected scan %s: %s", scan_id, e)
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
    except Exception:
        log.exception("failed to dispatch scan %s, will redeliver", scan_id)
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
    finally:
        if clone_path:
            git_utils.cleanup(clone_path)


def main():
    if not Config.ALLOWED_GIT_HOSTS:
        log.warning("ALLOWED_GIT_HOSTS is empty; all scan requests will be rejected")

    k8s_config.load_incluster_config()
    batch_api = client.BatchV1Api()
    conn = db.get_conn()

    params = pika.URLParameters(Config.RABBITMQ_URL)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.basic_qos(prefetch_count=1)

    def callback(ch, method, properties, body):
        handle_message(ch, method, properties, body, batch_api, conn)

    channel.basic_consume(queue=Config.REQUEST_QUEUE, on_message_callback=callback)
    log.info("dispatcher listening on %s", Config.REQUEST_QUEUE)
    channel.start_consuming()


if __name__ == "__main__":
    main()
