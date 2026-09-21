"""
TARVEX26
Domain Intelligence Engine
SIH26106 - Email Threat Detection and Forensic Intelligence

Provides:
- A / AAAA DNS records
- MX records
- TXT records
- SPF detection
- DMARC detection
- DKIM lookup
- NS records
- RDAP registration intelligence
- Domain infrastructure summary
"""

import re
import requests
import dns.resolver


# =========================================================
# DNS HELPER
# =========================================================

def _query_dns(domain, record_type):

    try:

        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        results = []

        for answer in answers:

            results.append(
                answer.to_text()
            )

        return results

    except Exception:

        return []


# =========================================================
# SPF ANALYSIS
# =========================================================

def analyze_spf(txt_records):

    spf_records = [
        record
        for record in txt_records
        if record.lower().startswith(
            "v=spf1"
        )
    ]

    if not spf_records:

        return {
            "present": False,
            "record": None,
            "mechanisms": [],
            "status": "NOT_FOUND"
        }

    record = spf_records[0]

    mechanisms = []

    for mechanism in [
        "include:",
        "a",
        "mx",
        "ip4:",
        "ip6:",
        "exists:",
        "all"
    ]:

        if mechanism in record.lower():

            mechanisms.append(
                mechanism
            )

    return {

        "present": True,

        "record": record,

        "mechanisms": mechanisms,

        "status": "FOUND"
    }


# =========================================================
# DMARC ANALYSIS
# =========================================================

def analyze_dmarc(domain):

    dmarc_domain = (
        f"_dmarc.{domain}"
    )

    records = _query_dns(
        dmarc_domain,
        "TXT"
    )

    dmarc_records = [
        record
        for record in records
        if record.lower().startswith(
            "v=dmarc1"
        )
    ]

    if not dmarc_records:

        return {

            "present": False,

            "record": None,

            "policy": "NOT_FOUND",

            "status": "NOT_FOUND"
        }

    record = dmarc_records[0]

    policy_match = re.search(
        r"(?:^|;)\s*p=([^;\s]+)",
        record,
        re.IGNORECASE
    )

    policy = (
        policy_match.group(1).upper()
        if policy_match
        else "UNSPECIFIED"
    )

    return {

        "present": True,

        "record": record,

        "policy": policy,

        "status": "FOUND"
    }


# =========================================================
# DKIM ANALYSIS
# =========================================================

def analyze_dkim(domain, selector=None):

    if not selector:

        return {

            "present": False,

            "selector": None,

            "record": None,

            "status":
                "SELECTOR_REQUIRED"
        }

    dkim_domain = (
        f"{selector}._domainkey.{domain}"
    )

    records = _query_dns(
        dkim_domain,
        "TXT"
    )

    if not records:

        return {

            "present": False,

            "selector": selector,

            "record": None,

            "status": "NOT_FOUND"
        }

    return {

        "present": True,

        "selector": selector,

        "record": " ".join(records),

        "status": "FOUND"
    }


# =========================================================
# RDAP DOMAIN INTELLIGENCE
# =========================================================

def analyze_rdap(domain):

    try:

        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=8,
            headers={
                "User-Agent":
                    "TARVEX26-SIH26106"
            }
        )

        if response.status_code != 200:

            return {

                "status":
                    "UNAVAILABLE",

                "domain":
                    domain,

                "http_status":
                    response.status_code
            }

        data = response.json()

        registrar = None

        entities = data.get(
            "entities",
            []
        )

        for entity in entities:

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" not in roles:
                continue

            vcard = entity.get(
                "vcardArray"
            )

            if not vcard:
                continue

            try:

                for item in vcard[1]:

                    if (
                        item[0] == "fn"
                        and len(item) > 3
                    ):

                        registrar = item[3]

                        break

            except Exception:
                pass

            if registrar:
                break

        status_values = []

        for status in data.get(
            "status",
            []
        ):

            status_values.append(
                status
            )

        nameservers = []

        for nameserver in data.get(
            "nameservers",
            []
        ):

            name = nameserver.get(
                "ldhName"
            )

            if name:
                nameservers.append(
                    name
                )

        return {

            "status":
                "FOUND",

            "domain":
                data.get(
                    "ldhName",
                    domain
                ),

            "handle":
                data.get(
                    "handle"
                ),

            "registrar":
                registrar,

            "domain_status":
                status_values,

            "nameservers":
                nameservers,

            "events":
                data.get(
                    "events",
                    []
                )
        }

    except Exception as error:

        return {

            "status":
                "UNAVAILABLE",

            "domain":
                domain,

            "error":
                str(error)
        }


# =========================================================
# MAIN DOMAIN ANALYZER
# =========================================================

def analyze_domain(
    domain,
    dkim_selector=None
):

    if not domain:

        return {

            "status":
                "INVALID_DOMAIN",

            "domain":
                None
        }

    domain = (
        str(domain)
        .strip()
        .lower()
        .strip(".")
    )

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    a_records = _query_dns(
        domain,
        "A"
    )

    aaaa_records = _query_dns(
        domain,
        "AAAA"
    )

    mx_records = _query_dns(
        domain,
        "MX"
    )

    txt_records = _query_dns(
        domain,
        "TXT"
    )

    ns_records = _query_dns(
        domain,
        "NS"
    )

    # -----------------------------------------------------
    # SPF
    # -----------------------------------------------------

    spf = analyze_spf(
        txt_records
    )

    # -----------------------------------------------------
    # DMARC
    # -----------------------------------------------------

    dmarc = analyze_dmarc(
        domain
    )

    # -----------------------------------------------------
    # DKIM
    # -----------------------------------------------------

    dkim = analyze_dkim(
        domain,
        dkim_selector
    )

    # -----------------------------------------------------
    # RDAP
    # -----------------------------------------------------

    rdap = analyze_rdap(
        domain
    )

    # -----------------------------------------------------
    # Findings
    # -----------------------------------------------------

    findings = []

    if not a_records and not aaaa_records:

        findings.append(
            "No A or AAAA record found."
        )

    if not mx_records:

        findings.append(
            "No MX record found."
        )

    if not spf["present"]:

        findings.append(
            "SPF record not found."
        )

    if not dmarc["present"]:

        findings.append(
            "DMARC record not found."
        )

    if dmarc["policy"] == "NONE":

        findings.append(
            "DMARC policy is set to NONE."
        )

    if rdap["status"] != "FOUND":

        findings.append(
            "RDAP registration information unavailable."
        )

    # -----------------------------------------------------
    # Infrastructure summary
    # -----------------------------------------------------

    return {

        "status":
            "ANALYZED",

        "domain":
            domain,

        "dns": {

            "A":
                a_records,

            "AAAA":
                aaaa_records,

            "MX":
                mx_records,

            "TXT":
                txt_records,

            "NS":
                ns_records
        },

        "spf":
            spf,

        "dmarc":
            dmarc,

        "dkim":
            dkim,

        "rdap":
            rdap,

        "infrastructure": {

            "ipv4_count":
                len(a_records),

            "ipv6_count":
                len(aaaa_records),

            "mx_count":
                len(mx_records),

            "nameserver_count":
                len(ns_records)
        },

        "findings":
            list(dict.fromkeys(
                findings
            )),

        "engine": {

            "name":
                "TARVEX26 Domain Intelligence Engine",

            "version":
                "1.0",

            "capabilities": [

                "DNS A analysis",

                "DNS AAAA analysis",

                "DNS MX analysis",

                "DNS TXT analysis",

                "DNS NS analysis",

                "SPF record analysis",

                "DMARC policy analysis",

                "DKIM selector lookup",

                "RDAP registration intelligence"

            ],

            "note":
                "DNS records and RDAP data are "
                "environment-dependent and may be "
                "unavailable for some domains."
        }
    }


# =========================================================
# MULTI-DOMAIN ANALYSIS
# =========================================================

def analyze_domains(
    domains,
    dkim_selector=None
):

    if not domains:

        return {

            "total_domains":
                0,

            "domains":
                [],

            "findings":
                []
        }

    results = []

    for domain in domains:

        results.append(
            analyze_domain(
                domain,
                dkim_selector
            )
        )

    all_findings = []

    for result in results:

        for finding in result.get(
            "findings",
            []
        ):

            all_findings.append(
                f"{result.get('domain')}: {finding}"
            )

    return {

        "total_domains":
            len(results),

        "domains":
            results,

        "findings":
            list(dict.fromkeys(
                all_findings
            )),

        "engine": {

            "name":
                "TARVEX26 Domain Intelligence Engine",

            "version":
                "1.0"
        }
    }