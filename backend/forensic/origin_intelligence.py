import json
import urllib.request
import urllib.error
import ipaddress


def is_public_ip(ip):
    """
    Check whether an IP address is publicly routable.
    Private/local IPs cannot provide useful internet geolocation.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_reserved
            and not address.is_link_local
        )

    except ValueError:
        return False


def geolocate_ip(ip):
    """
    Retrieve basic geolocation and network intelligence
    for a public IP address.
    """

    if not is_public_ip(ip):

        return {
            "ip": ip,
            "status": "unavailable",
            "reason": "Private or non-routable IP address"
        }

    try:

        url = f"https://ipwho.is/{ip}"

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TARVEX26-Email-Forensics"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if not data.get("success", False):

            return {
                "ip": ip,
                "status": "unavailable",
                "reason": data.get(
                    "message",
                    "Geolocation lookup failed"
                )
            }

        connection = data.get(
            "connection",
            {}
        )

        return {
            "ip": ip,
            "status": "success",

            "country": data.get(
                "country"
            ),

            "country_code": data.get(
                "country_code"
            ),

            "region": data.get(
                "region"
            ),

            "city": data.get(
                "city"
            ),

            "latitude": data.get(
                "latitude"
            ),

            "longitude": data.get(
                "longitude"
            ),

            "isp": connection.get(
                "isp"
            ),

            "organization": connection.get(
                "org"
            ),

            "asn": connection.get(
                "asn"
            )
        }

    except urllib.error.URLError:

        return {
            "ip": ip,
            "status": "unavailable",
            "reason": "Geolocation service unreachable"
        }

    except Exception as e:

        return {
            "ip": ip,
            "status": "unavailable",
            "reason": str(e)
        }


def analyze_origin(ip_addresses):
    """
    Analyze all extracted public IP addresses.
    """

    results = []

    for ip in ip_addresses:

        result = geolocate_ip(ip)

        results.append(result)

    return {
        "total_ips": len(ip_addresses),

        "public_ips": [
            result
            for result in results
            if result.get("status") == "success"
        ],

        "results": results
    }