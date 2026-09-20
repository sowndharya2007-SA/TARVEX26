def build_infrastructure_graph(
    headers,
    forensic_data,
    ip_intelligence=None,
    origin_data=None
):
    """
    Build a lightweight infrastructure relationship graph
    from the email's forensic indicators.
    """

    nodes = []
    relationships = []

    # ---------------------------------------------------------
    # EMAIL NODE
    # ---------------------------------------------------------

    nodes.append({
        "id": "email",
        "type": "email",
        "label": "Email"
    })

    # ---------------------------------------------------------
    # SENDER DOMAIN
    # ---------------------------------------------------------

    sender = headers.get("from")

    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1].strip(" >")

        domain_id = f"domain:{sender_domain}"

        nodes.append({
            "id": domain_id,
            "type": "domain",
            "label": sender_domain
        })

        relationships.append({
            "source": "email",
            "target": domain_id,
            "type": "SENDER_DOMAIN"
        })

    # ---------------------------------------------------------
    # REPLY-TO DOMAIN
    # ---------------------------------------------------------

    reply_to = headers.get("reply_to")

    if reply_to and "@" in reply_to:
        reply_domain = reply_to.split("@")[-1].strip(" >")

        reply_id = f"domain:{reply_domain}"

        if not any(node["id"] == reply_id for node in nodes):
            nodes.append({
                "id": reply_id,
                "type": "domain",
                "label": reply_domain
            })

        relationships.append({
            "source": "email",
            "target": reply_id,
            "type": "REPLY_TO_DOMAIN"
        })

    # ---------------------------------------------------------
    # IP ADDRESSES
    # ---------------------------------------------------------

    ip_addresses = forensic_data.get(
        "ip_addresses",
        []
    )

    for ip in ip_addresses:

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
    # RECEIVED / RELAY DOMAINS
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

        domain_id = f"relay:{domain}"

        if not any(node["id"] == domain_id for node in nodes):

            nodes.append({
                "id": domain_id,
                "type": "relay",
                "label": domain
            })

        relationships.append({
            "source": "email",
            "target": domain_id,
            "type": "RELAY"
        })

    # ---------------------------------------------------------
    # RETURN GRAPH
    # ---------------------------------------------------------

    return {
        "nodes": nodes,
        "relationships": relationships,
        "node_count": len(nodes),
        "relationship_count": len(relationships)
    }