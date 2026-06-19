#!/usr/bin/env python3
"""Publishes a single test scan request to RabbitMQ for local testing.

Configure via env vars rather than editing this file, so no real
credentials or internal hostnames ever end up committed here:

  GIT_URL   e.g. https://<token>@git.example.com/org/repo.git, or a
            plain https:// URL for a public repo with no auth needed
  GIT_REF   defaults to "main"
  ORG_ID    optional
"""
import json
import os
import uuid

import pika

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
GIT_URL = os.environ["GIT_URL"]
GIT_REF = os.environ.get("GIT_REF", "main")
ORG_ID = os.environ.get("ORG_ID")

scan_request = {
    "scan_id": str(uuid.uuid4()),
    "git_url": GIT_URL,
    "ref": GIT_REF,
    "org_id": ORG_ID,
}

params = pika.URLParameters(RABBITMQ_URL)
connection = pika.BlockingConnection(params)
channel = connection.channel()

channel.basic_publish(
    exchange="",
    routing_key="scan.requests",
    body=json.dumps(scan_request),
    properties=pika.BasicProperties(delivery_mode=2),
)

print(f"Published scan request: {scan_request['scan_id']}")
connection.close()
