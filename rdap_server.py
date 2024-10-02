from flask import Flask, jsonify, request, Response, make_response
from flask_cors import CORS
import whois
import datetime
import re
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

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
        "handle": whois_data.get('registry_domain_id', f"{domain_name.upper()}-DOMAIN"),
        "ldhName": domain_name.lower(),
        "unicodeName": domain_name,
        "status": [],
        "entities": [],
        "events": [],
        "nameservers": [],
        "secureDNS": {
            "delegationSigned": False
        },
        "links": [],
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
    event_actions = set()
    for event_name, event_action in [('creation_date', 'registration'),
                                     ('updated_date', 'last update of registration'),
                                     ('expiration_date', 'expiration')]:
        event_date = whois_data.get(event_name)
        if event_date:
            formatted_dates = format_date(event_date)
            if isinstance(formatted_dates, list):
                for date in formatted_dates:
                    if date and event_action not in event_actions:
                        events.append({
                            "eventAction": event_action,
                            "eventDate": date
                        })
                        event_actions.add(event_action)
            else:
                if formatted_dates and event_action not in event_actions:
                    events.append({
                        "eventAction": event_action,
                        "eventDate": formatted_dates
                    })
                    event_actions.add(event_action)
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
        # Normalize to lowercase and deduplicate
        ns_set = set(ns.lower() for ns in name_servers)
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
                ["kind", {}, "text", "org"]
            ]
        ]

        # Structured address
        if 'cosmotown' in registrar.lower():
            vcard_array[1].append([
                "adr",
                {
                    "label": "68 Willow Road\nMenlo Park\nCA\n94025\nUS"
                },
                "text",
                [
                    "",  # Post Office Box
                    "",  # Extended Address
                    "68 Willow Road",  # Street Address
                    "Menlo Park",  # Locality
                    "CA",  # Region
                    "94025",  # Postal Code
                    "US"  # Country (use country code)
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
        if not abuse_phone and 'cosmotown' in registrar.lower():
            abuse_phone = '+1.6503198930'

        if abuse_emails or abuse_phone:
            abuse_entity = {
                "objectClassName": "entity",
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Abuse Contact"],
                        ["kind", {}, "text", "individual"]
                    ]
                ]
            }
            if abuse_phone:
                abuse_entity['vcardArray'][1].append(["tel", {"type": ["voice", "work"]}, "uri", f"tel:{abuse_phone}"])
            if abuse_emails:
                for email in abuse_emails:
                    abuse_entity['vcardArray'][1].append(["email", {"type": "work"}, "text", email])
            registrar_entity['entities'].append(abuse_entity)

        rdap_response['entities'].append(registrar_entity)

    # Map 'secureDNS'
    rdap_response['secureDNS']['delegationSigned'] = whois_data.get('dnssec', '').lower() == 'signeddelegation'

    # Map 'links'
    rdap_response['links'] = [
        {
            "value": f"https://www.cosmotown.com/rdap/domain/{domain_name.lower()}",
            "rel": "self",
            "href": f"https://www.cosmotown.com/rdap/domain/{domain_name.lower()}",
            "mediaType": "application/rdap+json"
        }
    ]
    # Add registrar RDAP link if available
    registrar_whois_server = whois_data.get('registrar_whois_server') or whois_data.get('whois_server')
    if registrar_whois_server:
        rdap_response['links'].append({
            "value": f"https://{registrar_whois_server}/domain/{domain_name.lower()}",
            "rel": "related",
            "href": f"https://{registrar_whois_server}/domain/{domain_name.lower()}",
            "mediaType": "application/rdap+json"
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
                    "rel": "alternate",
                    "mediaType": "text/html"
                }
            ]
        },
        {
            "title": "Status Codes",
            "description": [
                "For more information on domain status codes, please visit https://icann.org/epp"
            ],
            "links": [
                {
                    "href": "https://icann.org/epp",
                    "rel": "alternate",
                    "mediaType": "text/html"
                }
            ]
        },
        {
            "title": "RDDS Inaccuracy Complaint Form",
            "description": [
                "URL of the ICANN RDDS Inaccuracy Complaint Form: https://www.icann.org/wicf"
            ],
            "links": [
                {
                    "href": "https://www.icann.org/wicf",
                    "rel": "alternate",
                    "mediaType": "text/html"
                }
            ]
        }
    ]

    # Map 'port43' (WHOIS Server)
    whois_server = whois_data.get('whois_server') or whois_data.get('registrar_whois_server')
    if whois_server:
        rdap_response['port43'] = whois_server

    return rdap_response

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/domain/<path:domain_name>', methods=['GET'])
def domain_lookup(domain_name):
    try:
        whois_data = whois.whois(domain_name)
        rdap_response = map_whois_to_rdap(whois_data, domain_name)
        response = make_response(json.dumps(rdap_response))
        response.headers['Content-Type'] = 'application/rdap+json'
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    except Exception as e:
        error_response = {
            "errorCode": 500,
            "title": "Internal Server Error",
            "description": [str(e)],
            "rdapConformance": [
                "rdap_level_0",
                "icann_rdap_technical_implementation_guide_0",
                "icann_rdap_response_profile_0"
            ]
        }
        response = make_response(json.dumps(error_response), 500)
        response.headers['Content-Type'] = 'application/rdap+json'
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

# [Other functions remain unchanged but ensure similar updates are applied]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9100)
