#!/usr/bin/env python3
"""
Threat Intelligence Feed Generator
Generates consumable threat intelligence feeds in multiple formats

Supported Formats:
- STIX 2.1 (Structured Threat Information Expression)
- JSON (custom format for SIEM ingestion)
- CSV (tabular format)
- OpenIOC (XML-based)
- MISP format (for MISP platform integration)

Author: Threat Intelligence Pipeline
Version: 1.0.0
"""

import json
import csv
from datetime import datetime, timedelta
from typing import Dict, List
from uuid import uuid4
import argparse
import sys

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("[!] Error: elasticsearch package not installed")
    print("[!] Install: pip install elasticsearch")
    sys.exit(1)


class ThreatFeedGenerator:
    """Generates threat intelligence feeds in multiple formats"""

    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        """Initialize threat feed generator"""
        self.es_host = es_host
        self.es_port = es_port

        # Connect to Elasticsearch
        try:
            self.es = Elasticsearch(
                [f"http://{es_host}:{es_port}"],
                timeout=30
            )

            if not self.es.ping():
                raise ConnectionError("Cannot connect to Elasticsearch")

            print(f"[+] Connected to Elasticsearch at {es_host}:{es_port}")

        except Exception as e:
            print(f"[!] Failed to connect to Elasticsearch: {e}")
            sys.exit(1)

    def generate_stix_bundle(self,
                            ioc_data: Dict,
                            output_file: str,
                            threat_actor: str = "Unknown"):
        """
        Generate STIX 2.1 bundle

        Args:
            ioc_data: IOC data from IOC extraction
            output_file: Output file path
            threat_actor: Threat actor name
        """
        print(f"[*] Generating STIX 2.1 bundle: {output_file}")

        bundle_id = f"bundle--{uuid4()}"
        created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Initialize STIX objects
        stix_objects = []

        # Create identity (your organization)
        identity_id = f"identity--{uuid4()}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": "Honeypot Threat Intelligence",
            "identity_class": "organization",
            "sectors": ["technology"]
        }
        stix_objects.append(identity)

        # Create threat actor
        threat_actor_id = f"threat-actor--{uuid4()}"
        threat_actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": threat_actor_id,
            "created": created,
            "modified": created,
            "name": threat_actor,
            "description": "Threat actor observed in honeypot infrastructure",
            "threat_actor_types": ["opportunist", "hacker"],
            "sophistication": "minimal",
            "resource_level": "individual",
            "primary_motivation": "personal-gain"
        }
        stix_objects.append(threat_actor_obj)

        # Create indicator for each IP
        for ip, data in ioc_data.get('ips', {}).items():
            indicator_id = f"indicator--{uuid4()}"

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": data.get('first_seen', created),
                "modified": data.get('last_seen', created),
                "name": f"Malicious IP: {ip}",
                "description": f"IP address observed in honeypot attacks ({data['count']} times)",
                "indicator_types": ["malicious-activity", "anomalous-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": data.get('first_seen', created),
                "labels": list(data.get('protocols', [])) + list(data.get('honeypots', [])),
                "confidence": int(data.get('confidence', 0.5) * 100),
                "created_by_ref": identity_id
            }
            stix_objects.append(indicator)

            # Create relationship to threat actor
            relationship_id = f"relationship--{uuid4()}"
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id,
                "created": created,
                "modified": created,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": threat_actor_id,
                "created_by_ref": identity_id
            }
            stix_objects.append(relationship)

        # Create indicators for file hashes
        for hash_value, data in ioc_data.get('file_hashes', {}).items():
            indicator_id = f"indicator--{uuid4()}"

            hash_type = data.get('type', 'unknown')
            pattern = f"[file:hashes.'{hash_type.upper()}' = '{hash_value}']"

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": data.get('first_seen', created),
                "modified": created,
                "name": f"Malware Sample: {data.get('filename', 'unknown')}",
                "description": f"Malware hash observed in honeypot",
                "indicator_types": ["malicious-activity", "malware"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": data.get('first_seen', created),
                "labels": ["malware"],
                "confidence": int(data.get('confidence', 0.9) * 100),
                "created_by_ref": identity_id
            }
            stix_objects.append(indicator)

        # Create indicators for domains
        for domain, data in ioc_data.get('domains', {}).items():
            indicator_id = f"indicator--{uuid4()}"

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": data.get('first_seen', created),
                "modified": created,
                "name": f"Malicious Domain: {domain}",
                "description": "Domain observed in honeypot malware downloads",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": data.get('first_seen', created),
                "confidence": int(data.get('confidence', 0.7) * 100),
                "created_by_ref": identity_id
            }
            stix_objects.append(indicator)

        # Create STIX bundle
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": stix_objects
        }

        # Write to file
        with open(output_file, 'w') as f:
            json.dump(bundle, f, indent=2)

        print(f"[+] STIX bundle generated with {len(stix_objects)} objects")

    def generate_json_feed(self, ioc_data: Dict, output_file: str):
        """
        Generate custom JSON threat feed

        Args:
            ioc_data: IOC data
            output_file: Output file path
        """
        print(f"[*] Generating JSON threat feed: {output_file}")

        feed = {
            "feed_metadata": {
                "feed_name": "Honeypot Threat Intelligence Feed",
                "version": "1.0",
                "generated": datetime.utcnow().isoformat(),
                "provider": "Honeypot TI Pipeline",
                "description": "IOCs extracted from multi-honeypot infrastructure",
                "feed_type": "indicator",
                "time_range": {
                    "start": ioc_data['metadata']['time_range_start'],
                    "end": ioc_data['metadata']['time_range_end']
                }
            },
            "statistics": ioc_data.get('statistics', {}),
            "indicators": {
                "ipv4": [],
                "domains": [],
                "urls": [],
                "file_hashes": [],
                "credentials": []
            }
        }

        # Add IP indicators
        for ip, data in ioc_data.get('ips', {}).items():
            feed['indicators']['ipv4'].append({
                "value": ip,
                "type": "ipv4-addr",
                "confidence": data.get('confidence', 0.5),
                "first_seen": data.get('first_seen'),
                "last_seen": data.get('last_seen'),
                "count": data.get('count', 0),
                "threat_score": data.get('threat_score', 0),
                "protocols": list(data.get('protocols', [])),
                "honeypots": list(data.get('honeypots', [])),
                "geoip": data.get('geoip', {}),
                "tags": ["honeypot", "malicious-activity"]
            })

        # Add file hash indicators
        for hash_value, data in ioc_data.get('file_hashes', {}).items():
            feed['indicators']['file_hashes'].append({
                "value": hash_value,
                "type": data.get('type', 'unknown'),
                "confidence": data.get('confidence', 0.9),
                "first_seen": data.get('first_seen'),
                "count": data.get('count', 0),
                "filename": data.get('filename'),
                "source_url": data.get('source_url'),
                "tags": ["malware", "honeypot"]
            })

        # Add domain indicators
        for domain, data in ioc_data.get('domains', {}).items():
            feed['indicators']['domains'].append({
                "value": domain,
                "type": "domain-name",
                "confidence": data.get('confidence', 0.7),
                "first_seen": data.get('first_seen'),
                "count": data.get('count', 0),
                "tags": ["c2", "malware-distribution", "honeypot"]
            })

        # Add URL indicators
        for url, data in ioc_data.get('urls', {}).items():
            feed['indicators']['urls'].append({
                "value": url,
                "type": "url",
                "confidence": data.get('confidence', 0.7),
                "first_seen": data.get('first_seen'),
                "count": data.get('count', 0),
                "method": data.get('method'),
                "tags": ["malware-distribution", "honeypot"]
            })

        # Add credential indicators (for defensive blocklisting)
        for cred, data in ioc_data.get('credentials', {}).items():
            feed['indicators']['credentials'].append({
                "username": data.get('username'),
                "password": data.get('password'),
                "count": data.get('count', 0),
                "success": data.get('success', False),
                "first_seen": data.get('first_seen'),
                "tags": ["credential-stuffing", "brute-force"]
            })

        # Write to file
        with open(output_file, 'w') as f:
            json.dump(feed, f, indent=2, default=str)

        print(f"[+] JSON feed generated with {sum(len(v) for v in feed['indicators'].values())} indicators")

    def generate_csv_feed(self, ioc_data: Dict, output_file: str):
        """
        Generate CSV threat feed (SIEM-friendly)

        Args:
            ioc_data: IOC data
            output_file: Output file path
        """
        print(f"[*] Generating CSV threat feed: {output_file}")

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow([
                'Indicator_Type',
                'Indicator_Value',
                'Confidence',
                'Threat_Score',
                'First_Seen',
                'Last_Seen',
                'Count',
                'Country',
                'Tags',
                'Description'
            ])

            # Write IP indicators
            for ip, data in ioc_data.get('ips', {}).items():
                writer.writerow([
                    'IPv4',
                    ip,
                    f"{data.get('confidence', 0.5):.2f}",
                    data.get('threat_score', 0),
                    data.get('first_seen', ''),
                    data.get('last_seen', ''),
                    data.get('count', 0),
                    data.get('geoip', {}).get('country', 'Unknown'),
                    'malicious-activity,honeypot',
                    f"Honeypot attacker IP ({data.get('count', 0)} attacks)"
                ])

            # Write hash indicators
            for hash_value, data in ioc_data.get('file_hashes', {}).items():
                writer.writerow([
                    f"Hash_{data.get('type', 'unknown').upper()}",
                    hash_value,
                    f"{data.get('confidence', 0.9):.2f}",
                    90,  # High threat score for malware
                    data.get('first_seen', ''),
                    '',
                    data.get('count', 0),
                    '',
                    'malware,honeypot',
                    f"Malware sample: {data.get('filename', 'unknown')}"
                ])

            # Write domain indicators
            for domain, data in ioc_data.get('domains', {}).items():
                writer.writerow([
                    'Domain',
                    domain,
                    f"{data.get('confidence', 0.7):.2f}",
                    70,
                    data.get('first_seen', ''),
                    '',
                    data.get('count', 0),
                    '',
                    'c2,malware-distribution,honeypot',
                    'Domain used in honeypot attacks'
                ])

        print(f"[+] CSV feed generated")

    def generate_misp_json(self, ioc_data: Dict, output_file: str):
        """
        Generate MISP-compatible JSON

        Args:
            ioc_data: IOC data
            output_file: Output file path
        """
        print(f"[*] Generating MISP JSON: {output_file}")

        event = {
            "Event": {
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "threat_level_id": "2",  # Medium
                "info": f"Honeypot IOCs - {datetime.utcnow().strftime('%Y-%m-%d')}",
                "published": True,
                "analysis": "2",  # Completed
                "distribution": "3",  # All communities
                "Attribute": []
            }
        }

        # Add IP attributes
        for ip, data in ioc_data.get('ips', {}).items():
            event["Event"]["Attribute"].append({
                "type": "ip-src",
                "category": "Network activity",
                "to_ids": True,
                "value": ip,
                "comment": f"Honeypot attacker ({data.get('count', 0)} attacks)",
                "distribution": "5",
                "Tag": [{"name": "honeypot"}, {"name": "malicious-activity"}]
            })

        # Add hash attributes
        for hash_value, data in ioc_data.get('file_hashes', {}).items():
            hash_type = data.get('type', 'md5')
            event["Event"]["Attribute"].append({
                "type": hash_type,
                "category": "Payload delivery",
                "to_ids": True,
                "value": hash_value,
                "comment": f"Malware: {data.get('filename', 'unknown')}",
                "distribution": "5",
                "Tag": [{"name": "honeypot"}, {"name": "malware"}]
            })

        # Add domain attributes
        for domain, data in ioc_data.get('domains', {}).items():
            event["Event"]["Attribute"].append({
                "type": "domain",
                "category": "Network activity",
                "to_ids": True,
                "value": domain,
                "comment": "C2 or malware distribution domain",
                "distribution": "5",
                "Tag": [{"name": "honeypot"}, {"name": "c2"}]
            })

        # Write to file
        with open(output_file, 'w') as f:
            json.dump(event, f, indent=2)

        print(f"[+] MISP JSON generated with {len(event['Event']['Attribute'])} attributes")


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Generate threat intelligence feeds in multiple formats'
    )

    parser.add_argument('--ioc-file', required=True,
                        help='Input IOC JSON file (from ioc_extraction.py)')
    parser.add_argument('--output-stix', default='threat_feed.stix.json',
                        help='STIX 2.1 output file')
    parser.add_argument('--output-json', default='threat_feed.json',
                        help='JSON output file')
    parser.add_argument('--output-csv', default='threat_feed.csv',
                        help='CSV output file')
    parser.add_argument('--output-misp', default='threat_feed.misp.json',
                        help='MISP JSON output file')
    parser.add_argument('--threat-actor', default='Opportunistic Attackers',
                        help='Threat actor name for STIX')

    args = parser.parse_args()

    print("=" * 60)
    print("THREAT INTELLIGENCE FEED GENERATOR")
    print("=" * 60)

    # Load IOC data
    print(f"[*] Loading IOC data from: {args.ioc_file}")
    try:
        with open(args.ioc_file, 'r') as f:
            ioc_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] IOC file not found: {args.ioc_file}")
        print("[!] Run ioc_extraction.py first to generate IOC data")
        sys.exit(1)

    # Initialize generator (Elasticsearch connection not required for feed generation)
    generator = ThreatFeedGenerator()

    # Generate feeds
    generator.generate_stix_bundle(ioc_data, args.output_stix, args.threat_actor)
    generator.generate_json_feed(ioc_data, args.output_json)
    generator.generate_csv_feed(ioc_data, args.output_csv)
    generator.generate_misp_json(ioc_data, args.output_misp)

    print("\n" + "=" * 60)
    print("FEED GENERATION COMPLETE")
    print("=" * 60)
    print(f"STIX 2.1: {args.output_stix}")
    print(f"JSON Feed: {args.output_json}")
    print(f"CSV Feed: {args.output_csv}")
    print(f"MISP JSON: {args.output_misp}")
    print("=" * 60)


if __name__ == '__main__':
    main()
