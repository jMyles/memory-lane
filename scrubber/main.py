#!/usr/bin/env python3
"""
Minimal secrets scrubber service.

Loads secrets from a JSON file at startup and provides an API to scrub text.
This container should be hardened and isolated - it's the only place secrets live.
"""

import json
import logging
import os
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Configure logging - never log actual content, just metrics
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Secrets Scrubber",
    description="Scrubs sensitive values from text",
    docs_url=None,  # Disable docs in production
    redoc_url=None,
)

# Load secrets at startup
SECRETS: List[str] = []
REDACTION_TEXT = "[REDACTED]"

# Values that should never be redacted even if they appear in the secrets list.
# These are typically database names, usernames, or other non-sensitive
# configuration values that happen to be stored alongside actual secrets.
DEFAULT_EXEMPTIONS = {
    'pickipedia',
    'mediawiki',
    'postgres',
    'postgresql',
    'mysql',
    'localhost',
    'root',
}


def is_exempt(value: str) -> bool:
    """Check if a value should be exempt from redaction."""
    return value.lower() in {e.lower() for e in DEFAULT_EXEMPTIONS}


def load_secrets():
    """Load secrets from JSON file."""
    global SECRETS
    secrets_file = os.environ.get('SECRETS_FILE', '/app/secrets.json')

    if not os.path.exists(secrets_file):
        logger.warning(f"Secrets file not found: {secrets_file}")
        return

    try:
        with open(secrets_file, 'r') as f:
            data = json.load(f)

        if isinstance(data, list):
            # Filter to non-empty strings with reasonable length, excluding exemptions
            all_secrets = [s for s in data if isinstance(s, str) and len(s) > 4]
            SECRETS = [s for s in all_secrets if not is_exempt(s)]
            exempted_count = len(all_secrets) - len(SECRETS)
            if exempted_count:
                logger.info(f"Exempted {exempted_count} non-sensitive values from redaction")
            logger.info(f"Loaded {len(SECRETS)} secrets")
        else:
            logger.warning("Secrets file is not a JSON list")
    except Exception as e:
        logger.error(f"Failed to load secrets: {e}")


# Load on startup
load_secrets()


class ScrubRequest(BaseModel):
    text: str


class ScrubResponse(BaseModel):
    text: str
    redacted: bool  # True if any secrets were found and replaced


class ScrubBatchRequest(BaseModel):
    texts: List[str]


class ScrubBatchResponse(BaseModel):
    texts: List[str]
    redacted_count: int


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "secrets_loaded": len(SECRETS)}


@app.post("/scrub", response_model=ScrubResponse)
def scrub(request: ScrubRequest):
    """Scrub secrets from a single text string."""
    result = request.text
    redacted = False

    for secret in SECRETS:
        if secret in result:
            result = result.replace(secret, REDACTION_TEXT)
            redacted = True

    return ScrubResponse(text=result, redacted=redacted)


@app.post("/scrub/batch", response_model=ScrubBatchResponse)
def scrub_batch(request: ScrubBatchRequest):
    """Scrub secrets from multiple text strings."""
    results = []
    redacted_count = 0

    for text in request.texts:
        result = text
        was_redacted = False

        for secret in SECRETS:
            if secret in result:
                result = result.replace(secret, REDACTION_TEXT)
                was_redacted = True

        results.append(result)
        if was_redacted:
            redacted_count += 1

    return ScrubBatchResponse(texts=results, redacted_count=redacted_count)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
