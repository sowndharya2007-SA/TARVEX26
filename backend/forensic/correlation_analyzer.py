import re


def extract_domain(value):
    """
    Extract a domain from an email address or text.
    """
    if not value:
        return None

    match = re.search(
        r'[\w.-]+@([\w.-]+\.\w+)',
        str(value)
    )

    if match:
        return match.group(1).lower()

    return None


def analyze_correlation(headers, forensic_data, origin_data=None):
    """
    Correlate email identities, domains, IP addresses
    and relay infrastructure.
    """

    nodes = []
    relationships = []
    findings = []

    # ---------------------------------------------------------
    # 1. EMAIL NODE
    # ---------------------------------------------------------

    sender = headers.get("from")
    reply_to = headers.get("reply_to")
    return_path = headers.get("return_path")

    nodes.append({
        "id": "email",
        "type": "email",
        "label": "Email"
    })

    # ---------------------------------------------------------
    # 2. SENDER DOMAIN
    # ---------------------------------------------------------

    sender_domain = extract_domain(sender)

    if sender_domain:
        nodes.append({
            "id": f"domain:{sender_domain}",
            "type": "domain",
            "label": sender_domain
        })

        relationships.append({
            "source": "email",
            "target": f"domain:{sender_domain}",
            "type": "SENDER_DOMAIN"
        })

    # ---------------------------------------------------------
    # 3. REPLY-TO DOMAIN
    # ---------------------------------------------------------

    reply_domain = extract_domain(reply_to)

    if reply_domain:
        nodes.append({
            "id": f"domain:{reply_domain}",
            "type": "domain",
            "label": reply_domain
        })

        relationships.append({
            "source": "email",
            "target": f"domain:{reply_domain}",
            "type": "REPLY_TO_DOMAIN"
        })

    # ---------------------------------------------------------
    # 4. RETURN-PATH DOMAIN
    # ---------------------------------------------------------

    return_domain = extract_domain(return_path)

    if return_domain:
        nodes.append({
            "id": f"domain:{return_domain}",
            "type": "domain",
            "label": return_domain
        })

        relationships.append({
            "source": "email",
            "target": f"domain:{return_domain}",
            "type": "RETURN_PATH_DOMAIN"
        })

    # ---------------------------------------------------------
    # 5. IP ADDRESSES
    # ---------------------------------------------------------

    ip_addresses = forensic_data.get(
        "ip_addresses",
        []
    )

    for index, ip in enumerate(ip_addresses):

        ip_id = f"ip:{ip}"

        nodes.append({
            "id": ip_id,
            "type": "ip",
            "label": ip
        })

        relationships.append({
            "source": "email",
            "target": ip_id,
            "type": "SOURCE_IP"
        })

    # ---------------------------------------------------------
    # 6. RELAY DOMAINS
    # ---------------------------------------------------------

    relay_analysis = forensic_data.get(
        "relay_analysis",
        {}
    )

    relay_domains = relay_analysis.get(
        "domains",
        []
    )

    for domain in relay_domains:

        if not domain:
            continue

        domain_id = f"domain:{domain}"

        if not any(
            node["id"] == domain_id
            for node in nodes
        ):
            nodes.append({
                "id": domain_id,
                "type": "domain",
                "label": domain
            })

        relationships.append({
            "source": "email",
            "target": domain_id,
            "type": "RELAY_DOMAIN"
        })

    # ---------------------------------------------------------
    # 7. DOMAIN MISMATCH ANALYSIS
    # ---------------------------------------------------------

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:

            findings.append(
                "Sender and Reply-To domains are different"
            )

            relationships.append({
                "source": f"domain:{sender_domain}",
                "target": f"domain:{reply_domain}",
                "type": "DOMAIN_MISMATCH"
            })

    # ---------------------------------------------------------
    # 8. RETURN-PATH MISMATCH
    # ---------------------------------------------------------

    if sender_domain and return_domain:

        if sender_domain != return_domain:

            findings.append(
                "Sender and Return-Path domains are different"
            )

            relationships.append({
                "source": f"domain:{sender_domain}",
                "target": f"domain:{return_domain}",
                "type": "RETURN_PATH_MISMATCH"
            })

    # ---------------------------------------------------------
    # 9. IP INTELLIGENCE
    # ---------------------------------------------------------

    origin_results = []

    if origin_data:

        origin_results = origin_data.get(
            "results",
            []
        )

    for result in origin_results:

        ip = result.get("ip")

        if not ip:
            continue

        ip_id = f"ip:{ip}"

        for key in [
            "country",
            "city",
            "organization",
            "asn"
        ]:

            value = result.get(key)

            if value:
                nodes.append({
                    "id": f"{key}:{value}",
                    "type": key,
                    "label": str(value)
                })

                relationships.append({
                    "source": ip_id,
                    "target": f"{key}:{value}",
                    "type": key.upper()
                })

    # ---------------------------------------------------------
    # 10. REMOVE DUPLICATE NODES
    # ---------------------------------------------------------

    unique_nodes = {}

    for node in nodes:
        unique_nodes[node["id"]] = node

    nodes = list(unique_nodes.values())

    # ---------------------------------------------------------
    # 11. REMOVE DUPLICATE RELATIONSHIPS
    # ---------------------------------------------------------

    unique_relationships = []

    seen_relationships = set()

    for relationship in relationships:

        key = (
            relationship["source"],
            relationship["target"],
            relationship["type"]
        )

        if key not in seen_relationships:

            seen_relationships.add(key)
            unique_relationships.append(
                relationship
            )

    relationships = unique_relationships

    # ---------------------------------------------------------
    # 12. RETURN CORRELATION GRAPH
    # ---------------------------------------------------------

    return {
        "nodes": nodes,
        "relationships": relationships,
        "findings": findings,
        "node_count": len(nodes),
        "relationship_count": len(relationships)
    }