#!/usr/bin/env python3
"""scripts/bedrock_hello.py - Bedrock Converse API hello-world and diagnostic check.

Verifies AWS credentials, region, model configuration, and exercises the Converse API.
If credentials or model access are unavailable, falls back gracefully and explains what is needed.
"""

import os
import sys

from dotenv import load_dotenv

# Load local environment variables if present
load_dotenv()

DEFAULT_REGION = os.getenv("AWS_REGION", "us-east-1")
DEFAULT_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")


def check_bedrock():
    print("=" * 60)
    print("HomeBOM - AWS Bedrock Converse API Diagnostic Check")
    print("=" * 60)
    print(f"Target AWS Region:   {DEFAULT_REGION}")
    print(f"Target Bedrock Model: {DEFAULT_MODEL_ID}")
    print("-" * 60)

    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError as e:
        print(f"[ERROR] boto3 is not installed: {e}")
        return False

    try:
        session = boto3.Session(region_name=DEFAULT_REGION)
        client = session.client("bedrock-runtime")

        print("[INFO] Attempting Bedrock Converse API call...")
        response = client.converse(
            modelId=DEFAULT_MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": "Hello Bedrock, confirm HomeBOM connectivity with one sentence."}],
                }
            ],
            inferenceConfig={
                "temperature": 0.0,
                "maxTokens": 64,
            },
        )

        output_text = response["output"]["message"]["content"][0]["text"]
        print("[SUCCESS] Bedrock Converse API responded:")
        print(f"  > {output_text.strip()}")
        print("-" * 60)
        return True

    except NoCredentialsError:
        print("[WARNING] No AWS credentials found.")
        print("To enable live Bedrock calls:")
        print("  1. Export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, (and AWS_SESSION_TOKEN if temporary)")
        print("  2. Or configure ~/.aws/credentials / SSO profile")
        print("  3. Set AWS_REGION and BEDROCK_MODEL_ID in .env or environment")
        print("[INFO] HomeBOM's deterministic template fallback will be active.")
        return False
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        print(f"[WARNING] Bedrock ClientError ({error_code}): {error_msg}")
        print("Common causes: model access not granted in AWS console, invalid region, or IAM permissions.")
        print("[INFO] HomeBOM's deterministic template fallback will be active.")
        return False
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] Unexpected error connecting to Bedrock: {e}")
        print("[INFO] HomeBOM's deterministic template fallback will be active.")
        return False


if __name__ == "__main__":
    success = check_bedrock()
    # Exit 0 regardless because template fallback is a first-class feature of HomeBOM
    sys.exit(0)
