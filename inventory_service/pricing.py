"""Pricing sync — pulls exchange rates from an internal pricing service."""

import requests

# A fixed, in-cluster endpoint we operate. It is never user-controlled, and we
# never pass user-supplied URLs or cross-host credentials.
PRICING_API = "http://pricing.internal.svc.cluster.local/v1/rates"


def fetch_rates():
    """Fetch current rates from the internal pricing API.

    SCA findings: requests 2.19.1 (e.g. CVE-2018-18074 — Authorization header
    leaked when a request is redirected to a different host) and its transitive
    urllib3 1.25.8 advisories.

    Verdict: NOT APPLICABLE in this usage. The URL is a constant internal host,
    we send no Authorization header, follow no user-controlled redirects, and use
    no proxies — so the redirect/proxy/CRLF advisories have no reachable trigger
    here. Keep the dependency current as hygiene, but it is not an exploitable
    finding for this service.
    """
    return requests.get(PRICING_API, timeout=5).json()
