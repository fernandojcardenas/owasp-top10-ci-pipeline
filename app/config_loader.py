import os
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        # FIX (A08:2021 Software and Data Integrity Failures): safe_load only builds plain
        # Python types (dict, list, str, int, etc.) from the YAML document. It cannot construct
        # arbitrary objects, so a tampered or attacker-controlled config file can no longer be
        # used to execute code when this file is loaded. See docs/vulnerabilities/07-insecure-yaml-deserialization.md.
        return yaml.safe_load(f)
