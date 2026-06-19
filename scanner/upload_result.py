#!/usr/bin/env python3
import argparse

import boto3


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--file", required=True)
    p.add_argument("--object-key", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--access-key", required=True)
    p.add_argument("--secret-key", required=True)
    args = p.parse_args()

    s3 = boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
    )
    s3.upload_file(args.file, args.bucket, args.object_key)


if __name__ == "__main__":
    main()
