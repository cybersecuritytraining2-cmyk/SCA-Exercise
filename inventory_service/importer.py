"""Bulk inventory import from a YAML file uploaded by an operator."""

import yaml


def import_inventory(uploaded_bytes):
    """Parse an uploaded inventory file and return the list of items."""
    return yaml.load(uploaded_bytes)
