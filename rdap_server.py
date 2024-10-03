from flask import Flask, request, make_response
from flask_cors import CORS
import whois
import datetime
import re
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

def parse_date(date_str):
    date_formats = [
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d"
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
                    formatted_dates.append(
                        parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
                    )
        return formatted_dates
    elif isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(dt, str):
        parsed_date = parse_date(dt)
        if parsed_date:
            return parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None

def generate_handle(domain_name):
    # Replace non-word characters with underscores
    unique_id = re.sub(r'\W', '_', domain_name)
    unique_id = unique_id[:80]  # Truncate to 80 characters
    repository_id = 'COSMOTOWN'
    handle = f"{unique_id}-{repository_id}"
    return handle


def extract_registry_domain_id(raw_text):
    match = re.search(r'Registry Domain ID:\s*(.+)', raw_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def map_whois_to_rdap(whois_data, domain_name):
    normalized_domain = domain_name.lower()
    raw_text = whois_data.text
    registry_domain_id = extract_registry_domain_id(raw_text)
    rdap_response = {
        "objectClassName": "domain",
        "handle": registry_domain_id or generate_handle(normalized_domain),
        "ldhName": normalized_domain,
        "unicodeName": domain_name,
        "status": [],
        "entities": [],
        "events": [],
        "nameservers": [],
        "secureDNS": {
            "delegationSigned": False
        },
        "links": [
            {
                "value": f"https://www.cosmotown.com/rdap/domain/"
                         f"{normalized_domain}",
                "rel": "self",
                "href": f"https://www.cosmotown.com/rdap/domain/"
                        f"{normalized_domain}",
                "type": "application/rdap+json"
            }
        ],
        "notices": [
            {
                "title": "Terms of Use",
                "description": [
                    "Service subject to Terms of Use."
                ],
                "links": [
                    {
                        "href": "https://www.cosmotown.com/terms",
                        "rel": "alternate"
                    }
                ]
            },
            {
                "title": "Status Codes",
                "description": [
                    "For more information on domain status codes, "
                    "please visit https://icann.org/epp"
                ],
                "links": [
                    {
                        "href": "https://icann.org/epp",
                        "rel": "alternate"
                    }
                ]
            },
            {
                "title": "RDDS Inaccuracy Complaint Form",
                "description": [
                    "URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf"
                ],
                "links": [
                    {
                        "href": "https://icann.org/wicf",
                        "rel": "alternate"
                    }
                ]
            }
        ],
        "rdapConformance": [
            "rdap_level_0",
            "icann_rdap_technical_implementation_guide_0",
            "icann_rdap_response_profile_0"
        ]
    }

    # Map 'status'
    status = whois_data.get('status') or whois_data.get('domain_status')
    if status:
        if isinstance(status, list):
            status_normalized = set()
            for s in status:
                s_clean = re.sub(r'\s*\(.*\)|\s*https?://\S+', '', s).strip()
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
    event_mapping = [
        ('creation_date', 'registration'),
        ('updated_date', 'last changed'),
        ('expiration_date', 'expiration')
    ]
    for event_name, event_action in event_mapping:
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
        "eventDate": datetime.datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    })
    rdap_response['events'] = events

    # Map 'nameservers'
    name_servers = whois_data.get('name_servers') or \
                   whois_data.get('name_server')
    if name_servers:
        if isinstance(name_servers, str):
            name_servers = name_servers.split()
        ns_set = set(ns.lower() for ns in name_servers)
        rdap_response['nameservers'] = [
            {
                "objectClassName": "nameserver",
                "ldhName": ns
            } for ns in ns_set
        ]

    # Map 'entities' (Registrar)
    registrar = whois_data.get('registrar')
    if registrar:
        registrar_iana_id = whois_data.get('registrar_iana_id', '')
        if not registrar_iana_id:
            if 'cosmotown' in registrar.lower():
                registrar_iana_id = '1509'
            elif 'markmonitor' in registrar.lower():
                registrar_iana_id = '292'

        vcard_array = [
            "vcard",
            [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", registrar],
                #["kind", {}, "text", "org"],
                #["adr", {}, "text", [ "", "", "68 Willow Road", "Menlo Park", "CA", "94025", "US" ]]
            ]
        ]

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

        # Add 'abuse' contact
        abuse_emails = ['abuse@cosmotown.com']
        abuse_phone = '+1.6503198930'

        abuse_entity = {
            "objectClassName": "entity",
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Abuse Contact"],
                    ["kind", {}, "text", "individual"],
                    ["tel", {"type": ["voice", "work"]},
                     "uri", f"tel:{abuse_phone}"],
                    ["email", {"type": "work"}, "text",
                     abuse_emails[0]]
                ]
            ]
        }
        registrar_entity['entities'].append(abuse_entity)
        rdap_response['entities'].append(registrar_entity)

    # Map 'secureDNS'
    rdap_response['secureDNS']['delegationSigned'] = \
        whois_data.get('dnssec', '').lower() == 'signeddelegation'

    # Map 'port43' (WHOIS Server)
    whois_server = whois_data.get('whois_server') or \
                   whois_data.get('registrar_whois_server')
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
        normalized_domain = domain_name.lower()
        whois_data = whois.whois(normalized_domain)
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

if __name__ == '__main__':
    app.run(host='::', port=9100)  # Listen on IPv6 and IPv4
