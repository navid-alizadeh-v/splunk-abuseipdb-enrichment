#!/usr/bin/env python3

import sys

import splunk.Intersplunk

from abuseipdb_core import enrich_ip


ENRICHMENT_FIELDS = [
    "abuseipdb_ipAddress",
    "abuseipdb_isWhitelisted",
    "abuseipdb_abuseConfidenceScore",
    "abuseipdb_countryCode",
    "abuseipdb_usageType",
    "abuseipdb_isp",
    "abuseipdb_domain",
    "abuseipdb_hostnames",
    "abuseipdb_totalReports",
    "abuseipdb_lastReportedAt",
    "abuseipdb_check_mode",
    "abuseipdb_cache_hit",
    "abuseipdb_cache_age_days",
    "abuseipdb_status",
    "abuseipdb_error",
]


def main():
    is_getinfo, sys.argv = splunk.Intersplunk.isGetInfo(sys.argv)

    if is_getinfo:
        splunk.Intersplunk.outputInfo(
            True, False, False, False, None
        )
        return 0

    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
    ip_field = kwargs.get("ip")

    if not ip_field:
        splunk.Intersplunk.parseError(
            "Required argument: ip=FIELD"
        )
        return 2

    results, dummyresults, settings = (
        splunk.Intersplunk.getOrganizedResults()
    )

    for row in results:
        try:
            enriched = enrich_ip(row.get(ip_field, ""))
        except Exception as exc:
            enriched = {
                "abuseipdb_check_mode": "not_checked",
                "abuseipdb_cache_hit": False,
                "abuseipdb_cache_age_days": "",
                "abuseipdb_status": "internal_error",
                "abuseipdb_error": type(exc).__name__,
            }

        row.update(enriched)

    splunk.Intersplunk.outputResults(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
