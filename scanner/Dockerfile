# Build with --build-arg BASE_TAG=golang|node|python|maven|gradle|ruby|dotnet|php|linux
ARG BASE_TAG=linux
FROM snyk/snyk:${BASE_TAG}

# psycopg2 has no manylinux wheel for musl/Alpine, so build it against
# postgresql-dev then drop the build toolchain to keep the image small.
RUN apk add --no-cache python3 py3-pip git postgresql-libs \
    && apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev python3-dev \
    && pip3 install --no-cache-dir --break-system-packages boto3 pika psycopg2-binary \
    && apk del .build-deps

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY upload_result.py /usr/local/bin/upload_result.py
COPY summarize.py /usr/local/bin/summarize.py
COPY publish_result.py /usr/local/bin/publish_result.py
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
