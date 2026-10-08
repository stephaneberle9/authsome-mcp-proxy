"""Shared fixtures: a DynamoDB endpoint for the store backend tests."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import boto3
import pytest
from moto.server import ThreadedMotoServer

REGION = "eu-central-1"


@pytest.fixture(scope="session")
def dynamodb_endpoint() -> Iterator[str]:
    """moto's DynamoDB emulation, served on an ephemeral 127.0.0.1 port.

    Server mode because the store talks through aioboto3, whose aiohttp
    transport moto's in-process botocore patches do not reach. Bound to the
    IPv4 loopback literal: ``localhost`` can resolve to ``::1`` first, which
    the server does not listen on.
    """
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.stop()


@pytest.fixture
def aws_env(dynamodb_endpoint: str, monkeypatch: pytest.MonkeyPatch, tmp_path) -> str:
    """Point the AWS SDK at the emulator, with throwaway credentials.

    ``AWS_ENDPOINT_URL_DYNAMODB`` is the SDK's own per-service endpoint
    override, so the proxy needs no endpoint setting of its own to be tested
    -- or to run against DynamoDB Local. The config and credentials files are
    pointed at nothing so a developer's real AWS profile cannot leak in.
    """
    monkeypatch.setenv("AWS_ENDPOINT_URL_DYNAMODB", dynamodb_endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    return dynamodb_endpoint


def dynamodb_client(endpoint: str):
    return boto3.client("dynamodb", endpoint_url=endpoint, region_name=REGION)


@pytest.fixture
def dynamodb_table(aws_env: str) -> str:
    """A fresh table with the schema the README documents for infrastructure."""
    name = f"authsome-mcp-proxy-{uuid.uuid4().hex[:12]}"
    client = dynamodb_client(aws_env)
    client.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "collection", "KeyType": "HASH"},
            {"AttributeName": "key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "collection", "AttributeType": "S"},
            {"AttributeName": "key", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    client.update_time_to_live(
        TableName=name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
    )
    return name
