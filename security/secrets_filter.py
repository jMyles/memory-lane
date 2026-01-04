"""
Secrets filtering to prevent leaking sensitive data.

Loads secrets from Ansible vault and provides scrubbing functions
to redact those secrets from text, JSON, and other data structures
before they're written to databases, sent to external APIs, etc.
"""

import os
import re
import json
import yaml
import subprocess
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)


class SecretsFilter:
    """
    Filter for redacting secrets from text and data structures.

    Loads secrets from Ansible vault and provides methods to scrub
    sensitive values before they're persisted or transmitted.
    """

    # Values that should never be redacted even if they appear in the vault.
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

    def __init__(self, vault_path: str = None, vault_password: str = None,
                 secrets_json: str = None, exemptions: List[str] = None):
        """
        Initialize the secrets filter.

        Args:
            vault_path: Path to encrypted Ansible vault file
            vault_password: Password to decrypt vault (reads from env if not provided)
            secrets_json: JSON-encoded list of secrets (alternative to vault)
            exemptions: Additional values to exempt from redaction
        """
        self.secrets: List[str] = []
        self.redaction_text = "[REDACTED:VAULT_SECRET]"

        # Build exemption set from defaults plus any custom exemptions
        self.exemptions = set(self.DEFAULT_EXEMPTIONS)
        if exemptions:
            self.exemptions.update(exemptions)

        # First try loading from JSON (preferred - no vault password needed at runtime)
        if secrets_json:
            self._load_from_json(secrets_json)
        elif vault_path:
            self._load_vault_secrets(vault_path, vault_password)

        logger.info(f"SecretsFilter initialized with {len(self.secrets)} secret values to scrub")

    def _is_exempt(self, value: str) -> bool:
        """Check if a value should be exempt from redaction."""
        return value.lower() in {e.lower() for e in self.exemptions}

    def _load_from_json(self, secrets_json: str):
        """Load secrets from a JSON-encoded list."""
        try:
            secrets_list = json.loads(secrets_json)
            if isinstance(secrets_list, list):
                all_secrets = [s for s in secrets_list if isinstance(s, str) and s]
                self.secrets = [s for s in all_secrets if not self._is_exempt(s)]
                exempted_count = len(all_secrets) - len(self.secrets)
                if exempted_count:
                    logger.info(f"Exempted {exempted_count} non-sensitive values from redaction")
                logger.info(f"Loaded {len(self.secrets)} secrets from JSON")
            else:
                logger.warning("SCRUB_SECRETS is not a JSON list")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse secrets JSON: {e}")

    def _load_vault_secrets(self, vault_path: str, vault_password: str = None):
        """
        Load secrets from encrypted Ansible vault.

        Decrypts the vault and extracts all vault_* variable values
        to build the list of secrets to scrub.
        """
        vault_path = Path(vault_path)
        if not vault_path.exists():
            logger.warning(f"Vault file not found: {vault_path}")
            return

        # Get vault password from parameter or environment
        password = vault_password or os.environ.get('ANSIBLE_VAULT_PASSWORD')
        if not password:
            logger.warning("No vault password provided, skipping vault secrets loading")
            return

        try:
            # Decrypt vault using ansible-vault
            result = subprocess.run(
                ['ansible-vault', 'view', str(vault_path)],
                input=password.encode(),
                capture_output=True,
                check=True
            )

            # Parse decrypted YAML
            vault_data = yaml.safe_load(result.stdout)

            # Extract all vault_* variable values, skipping exempted ones
            exempted_count = 0
            for key, value in vault_data.items():
                if key.startswith('vault_') and isinstance(value, str) and value:
                    if self._is_exempt(value):
                        exempted_count += 1
                        logger.debug(f"Exempted non-sensitive vault variable: {key}")
                    else:
                        self.secrets.append(value)
                        logger.debug(f"Loaded secret from vault variable: {key}")

            if exempted_count:
                logger.info(f"Exempted {exempted_count} non-sensitive values from redaction")
            logger.info(f"Loaded {len(self.secrets)} secrets from vault")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to decrypt vault: {e.stderr.decode()}")
        except Exception as e:
            logger.error(f"Error loading vault secrets: {e}")

    def scrub(self, text: str) -> str:
        """
        Scrub secrets from a text string.

        Args:
            text: String that may contain secrets

        Returns:
            String with secrets replaced by redaction text
        """
        if not text:
            return text

        result = text
        for secret in self.secrets:
            if secret in result:
                result = result.replace(secret, self.redaction_text)

        return result

    def scrub_json(self, data: Union[Dict, List, Any]) -> Union[Dict, List, Any]:
        """
        Recursively scrub secrets from JSON-like data structures.

        Args:
            data: Dict, list, or primitive value

        Returns:
            Same structure with secrets scrubbed
        """
        if isinstance(data, dict):
            return {k: self.scrub_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.scrub_json(item) for item in data]
        elif isinstance(data, str):
            return self.scrub(data)
        else:
            return data

    def scrub_jsonl_line(self, line: str) -> str:
        """
        Scrub secrets from a JSONL line.

        Parses the JSON, scrubs it, and returns as JSONL string.

        Args:
            line: JSONL line (JSON object as string)

        Returns:
            Scrubbed JSONL line
        """
        try:
            data = json.loads(line)
            scrubbed = self.scrub_json(data)
            return json.dumps(scrubbed)
        except json.JSONDecodeError:
            # If it's not valid JSON, just scrub as text
            return self.scrub(line)

    def add_secret(self, secret: str):
        """
        Manually add a secret value to scrub.

        Useful for runtime-discovered secrets or environment variables.
        Respects exemption list - exempt values won't be added.
        """
        if secret and secret not in self.secrets and not self._is_exempt(secret):
            self.secrets.append(secret)
            logger.debug(f"Added secret to filter (length: {len(secret)})")

    def add_exemption(self, value: str):
        """
        Add a value to the exemption list.

        Exempted values will not be redacted even if they appear in the vault.
        Also removes the value from secrets if it was already loaded.
        """
        if value:
            self.exemptions.add(value.lower())
            # Remove from secrets if already present
            self.secrets = [s for s in self.secrets if s.lower() != value.lower()]
            logger.debug(f"Added exemption: {value}")

    def add_env_secrets(self, *env_var_names: str):
        """
        Add secrets from environment variables.

        Args:
            *env_var_names: Names of environment variables containing secrets
        """
        for var_name in env_var_names:
            value = os.environ.get(var_name)
            if value:
                self.add_secret(value)
                logger.debug(f"Added secret from env var: {var_name}")
