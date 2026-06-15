"""Pricing sync — pulls exchange rates from an internal pricing service."""

import requests

PRICING_API = "http://pricing.internal.svc.cluster.local/v1/rates"


def fetch_rates():
    """Fetch current rates from the internal pricing API."""
    return requests.get(PRICING_API, timeout=5).json()
