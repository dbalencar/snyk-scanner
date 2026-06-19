# Build with --build-arg BASE_TAG=golang|node|python|maven|gradle|ruby|dotnet|php|linux
ARG BASE_TAG=linux
FROM snyk/snyk:${BASE_TAG}

# snyk/snyk:* images vary by base distro across tags; detect apk vs apt
# rather than assuming one. psycopg2 has no manylinux wheel for musl, so on
# Alpine it needs to be built against postgresql-dev; on glibc/Debian the
# prebuilt wheel just works.
RUN if command -v apk >/dev/null 2>&1; then \
      apk add --no-cache python3 py3-pip git postgresql-libs && \
      apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev python3-dev && \
      pip3 install --no-cache-dir --break-system-packages boto3 pika psycopg2-binary uv && \
      apk del .build-deps; \
    elif command -v apt-get >/dev/null 2>&1; then \
      apt-get update && \
      apt-get install -y --no-install-recommends python3 python3-pip git && \
      rm -rf /var/lib/apt/lists/* && \
      pip3 install --no-cache-dir --break-system-packages boto3 pika psycopg2-binary uv; \
    else \
      echo "unsupported base image: neither apk nor apt-get found" >&2 && exit 1; \
    fi

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY upload_result.py /usr/local/bin/upload_result.py
COPY summarize.py /usr/local/bin/summarize.py
COPY publish_result.py /usr/local/bin/publish_result.py
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
