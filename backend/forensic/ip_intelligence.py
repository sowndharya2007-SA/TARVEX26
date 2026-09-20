import ipaddress


def analyze_ip(ip):
    """
    Analyze an extracted IP address and return
    basic origin intelligence.
    """

    try:
        ip_obj = ipaddress.ip_address(ip)

        result = {
            "ip": ip,
            "version": ip_obj.version,
            "type": "Public IP",
            "country": "Unknown",
            "city": "Unknown",
            "organization": "Unknown",
            "asn": "Unknown",
            "latitude": None,
            "longitude": None
        }

        # Identify special/private/reserved addresses
        if ip_obj.is_private:
            result["type"] = "Private IP"

        elif ip_obj.is_loopback:
            result["type"] = "Loopback IP"

        elif ip_obj.is_reserved:
            result["type"] = "Reserved IP"

        elif ip_obj.is_global:
            result["type"] = "Public IP"

        return result

    except ValueError:
        return {
            "ip": ip,
            "type": "Invalid IP",
            "country": "Unknown",
            "city": "Unknown",
            "organization": "Unknown",
            "asn": "Unknown",
            "latitude": None,
            "longitude": None
        }


def analyze_ips(ip_addresses):
    """
    Analyze multiple extracted IP addresses.
    """

    results = []

    for ip in ip_addresses:
        results.append(analyze_ip(ip))

    return {
        "total_ips": len(results),
        "results": results
    }