from flask import Flask, jsonify, request, Response
import whois
import datetime
import re

app = Flask(__name__)

def parse_date(date_str):
    """
    Parses a date string into a datetime object.
    """
    date_formats = [
        "%Y-%m-%d %H:%M:%S%z",  # e.g., "2024-08-02 02:17:33+00:00"
        "%Y-%m-%d %H:%M:%S",    # e.g., "2019-09-09 15:39:04"
        "%Y-%m-%dT%H:%M:%SZ",   # e.g., "2024-08-02T02:17:33Z"
        "%Y-%m-%d"              # e.g., "2024-08-02"
    ]
    for fmt in date_formats:
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

def format_date(dt):
    if isinstance(dt, list):
        formatted_dates = []
        for d in dt:
            if isinstance(d, datetime.datetime):
                formatted_dates.append(d.strftime("%Y-%m-%dT%H:%M:%SZ"))
            elif isinstance(d, str):
                parsed_date = parse_date(d)
                if parsed_date:
                    formatted_dates.append(parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return formatted_dates
    elif isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(dt, str):
        parsed_date = parse_date(dt)
        if parsed_date:
            return parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None

def map_whois_to_rdap(whois_data, domain_name):
    rdap_response = {
        "objectClassName": "domain",
        "handle": whois_data.get('registry_domain_id', ''),
        "ldhName": domain_name.upper(),
        "status": [],
        "entities": [],
        "events": [],
        "nameservers": [],
        "links": [],
        "secureDNS": {
            "delegationSigned": False
        },
        "notices": [],
        "rdapConformance": [
            "rdap_level_0",
            "icann_rdap_technical_implementation_guide_0",
            "icann_rdap_response_profile_0"
        ],
    }

    if whois_data is None:
        return rdap_response

    # Map 'status'
    status = whois_data.get('status') or whois_data.get('domain_status')
    if status:
        if isinstance(status, list):
            # Normalize and deduplicate statuses
            status_normalized = set()
            for s in status:
                # Remove URLs and parentheses
                s_clean = re.sub(r'\s*\(.*\)|\s*https?://\S+', '', s).strip()
                # Insert spaces before capital letters
                s_with_spaces = re.sub(r'(?<!^)(?=[A-Z])', ' ', s_clean)
                s_lower = s_with_spaces.lower()
                status_normalized.add(s_lower)
            rdap_response['status'] = list(status_normalized)
        else:
            s_clean = re.sub(r'\s*\(.*\)|\s*https?://\S+', '', status).strip()
            s_with_spaces = re.sub(r'(?<!^)(?=[A-Z])', ' ', s_clean)
            s_lower = s_with_spaces.lower()
            rdap_response['status'] = [s_lower]

    # Map 'events'
    events = []
    for event_name, event_action in [('creation_date', 'registration'),
                                     ('updated_date', 'last changed'),
                                     ('expiration_date', 'expiration')]:
        event_date = whois_data.get(event_name)
        if event_date:
            formatted_dates = format_date(event_date)
            if isinstance(formatted_dates, list):
                for date in formatted_dates:
                    if date:
                        events.append({
                            "eventAction": event_action,
                            "eventDate": date
                        })
            else:
                if formatted_dates:
                    events.append({
                        "eventAction": event_action,
                        "eventDate": formatted_dates
                    })
    # Add 'last update of RDAP database' event
    events.append({
        "eventAction": "last update of RDAP database",
        "eventDate": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    })
    rdap_response['events'] = events

    # Map 'nameservers'
    name_servers = whois_data.get('name_servers') or whois_data.get('name_server')
    if name_servers:
        if isinstance(name_servers, str):
            name_servers = name_servers.split()
        # Normalize to uppercase and deduplicate
        ns_set = set(ns.upper() for ns in name_servers)
        rdap_response['nameservers'] = [{"objectClassName": "nameserver", "ldhName": ns} for ns in ns_set]

    # Map 'entities' (Registrar)
    registrar = whois_data.get('registrar')
    if registrar:
        # Set IANA ID manually for known registrars
        registrar_iana_id = whois_data.get('registrar_iana_id', '')
        if not registrar_iana_id:
            if 'cosmotown' in registrar.lower():
                registrar_iana_id = '1509'
            elif 'markmonitor' in registrar.lower():
                registrar_iana_id = '292'
            # Add more registrars as needed

        # Build vCard for registrar
        vcard_array = [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", registrar],
            ]
        ]

        # Hardcode address for Cosmotown
        if 'cosmotown' in registrar.lower():
            vcard_array[1].append([
                "adr",
                {},
                "text",
                [
                    None,
                    None,
                    "68 Willow Road",
                    "Menlo Park",
                    "CA",
                    "94025",
                    "US"
                ]
            ])

        registrar_entity = {
            "objectClassName": "entity",
            "handle": registrar_iana_id,
            "roles": ["registrar"],
            "publicIds": [
                {
                    "type": "IANA Registrar ID",
                    "identifier": registrar_iana_id
                }
            ],
            "vcardArray": vcard_array,
            "entities": []
        }

        # Add 'abuse' contact if available
        abuse_emails = None
        abuse_phone = whois_data.get('registrar_abuse_contact_phone')
        emails = whois_data.get('emails')
        if emails:
            if isinstance(emails, list):
                abuse_emails = [email for email in emails if 'abuse' in email.lower()]
            elif 'abuse' in emails.lower():
                abuse_emails = [emails]
        if not abuse_emails and 'cosmotown' in registrar.lower():
            # Hardcode abuse email for Cosmotown
            abuse_emails = ['abuse@cosmotown.com']

        if abuse_emails or abuse_phone:
            abuse_entity = {
                "objectClassName": "entity",
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Abuse Contact"]
                    ]
                ]
            }
            if abuse_phone:
                abuse_entity['vcardArray'][1].append(["tel", {"type": "voice"}, "uri", f"tel:{abuse_phone}"])
            if abuse_emails:
                for email in abuse_emails:
                    abuse_entity['vcardArray'][1].append(["email", {}, "text", email])
            registrar_entity['entities'].append(abuse_entity)

        # Add 'privacy' contact if available
        privacy_emails = None
        if emails:
            if isinstance(emails, list):
                privacy_emails = [email for email in emails if 'privacy' in email.lower()]
            elif 'privacy' in emails.lower():
                privacy_emails = [emails]
        if not privacy_emails and 'cosmotown' in registrar.lower():
            # Hardcode privacy email for Cosmotown
            privacy_emails = ['privacy@cosmotown.com']

        if privacy_emails:
            privacy_entity = {
                "objectClassName": "entity",
                "roles": ["privacy"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Privacy Contact"]
                    ]
                ]
            }
            for email in privacy_emails:
                privacy_entity['vcardArray'][1].append(["email", {}, "text", email])
            registrar_entity['entities'].append(privacy_entity)

        rdap_response['entities'].append(registrar_entity)

    # Map 'secureDNS'
    rdap_response['secureDNS']['delegationSigned'] = whois_data.get('dnssec', '').lower() == 'signeddelegation'

    # Map 'links'
    rdap_response['links'] = [
        {
            "value": f"https://www.cosmotown.com/rdap/domain/{domain_name.upper()}",
            "rel": "self",
            "href": f"https://www.cosmotown.com/rdap/domain/{domain_name.upper()}",
            "type": "application/rdap+json"
        }
    ]
    # Add registrar RDAP link if available
    registrar_whois_server = whois_data.get('registrar_whois_server') or whois_data.get('whois_server')
    if registrar_whois_server:
        rdap_response['links'].append({
            "value": f"https://{registrar_whois_server}/domain/{domain_name.upper()}",
            "rel": "related",
            "href": f"https://{registrar_whois_server}/domain/{domain_name.upper()}",
            "type": "application/rdap+json"
        })

    # Map 'notices'
    rdap_response['notices'] = [
        {
            "title": "Terms of Use",
            "description": [
                "Service subject to Terms of Use."
            ],
            "links": [
                {
                    "href": "https://www.cosmotown.com/terms",
                    "type": "text/html"
                }
            ]
        }
    ]

    # Map 'port43' (WHOIS Server)
    whois_server = whois_data.get('whois_server') or whois_data.get('registrar_whois_server')
    if whois_server:
        rdap_response['port43'] = whois_server

    return rdap_response

@app.route('/domain/<domain_name>', methods=['GET'])
def domain_lookup(domain_name):
    try:
        whois_data = whois.whois(domain_name)
        rdap_response = map_whois_to_rdap(whois_data, domain_name)
        response = jsonify(rdap_response)
        response.headers['Content-Type'] = 'application/rdap+json'
        return response
    except Exception as e:
        error_response = {
            "errorCode": 500,
            "title": "Internal Server Error",
            "description": [
                str(e)
            ],
            "rdapConformance": [
                "rdap_level_0",
                "icann_rdap_technical_implementation_guide_0",
                "icann_rdap_response_profile_0"
            ]
        }
        response = jsonify(error_response)
        response.headers['Content-Type'] = 'application/rdap+json'
        return response, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3030)