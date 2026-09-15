import os
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        # VULN (A08:2021 Software and Data Integrity Failures / CWE-502 Insecure Deserialization):
        # yaml.load() with the default Loader can construct arbitrary Python objects from the
        # YAML input, which allows code execution if an attacker ever controls this file's
        # contents. This should use yaml.safe_load() instead.
        return yaml.load(f, Loader=yaml.Loader)
