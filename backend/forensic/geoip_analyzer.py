import ipaddress
import urllib.request
import json


def analyze_ips(ip_addresses):
    """
    Analyze extracted IP addresses and return
    geolocation and infrastructure information.
    """

    results = []

    for ip in ip_addresses:

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Private/local IPs cannot provide useful public geolocation
            if ip_obj.is_private or ip_obj.is_loopback:
                results.append({
                    "ip": ip,
                    "type": "Private/Local",
                    "country": "Local Network",
                    "city": "N/A",
                    "organization": "Private Network",
                    "asn": "N/A"
                })
                continue

            # Public IP geolocation lookup
            url = f"https://ipwho.is/{ip}"

            with urllib.request.urlopen(
                url,
                timeout=5
            ) as response:

                data = json.loads(
                    response.read().decode("utf-8")
                )

            if data.get("success"):

                connection = data.get("connection", {})

                results.append({
                    "ip": ip,
                    "type": "Public IPv4" if ip_obj.version == 4 else "Public IPv6",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "organization": connection.get(
                        "org",
                        "Unknown"
                    ),
                    "asn": connection.get(
                        "asn",
                        "Unknown"
                    ),
                    "isp": connection.get(
                        "isp",
                        "Unknown"
                    ),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude")
                })

            else:

                results.append({
                    "ip": ip,
                    "type": "Public",
                    "country": "Unknown",
                    "city": "Unknown",
                    "organization": "Unknown",
                    "asn": "Unknown"
                })

        except Exception as e:

            results.append({
                "ip": ip,
                "type": "Unknown",
                "country": "Unavailable",
                "city": "Unavailable",
                "organization": "Unavailable",
                "asn": "Unavailable",
                "error": str(e)
            })

    return {
        "total_ips": len(ip_addresses),
        "results": results
    }