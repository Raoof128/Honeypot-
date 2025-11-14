#!/usr/bin/env python3
"""
IOC Extraction Engine for Honeypot Threat Intelligence
Extracts Indicators of Compromise (IOCs) from Elasticsearch honeypot logs

Outputs:
- JSON: Structured IOC dataset
- CSV: Tabular format for SIEM ingestion
- STIX 2.1: Industry-standard threat intelligence format
- Markdown: Human-readable threat report

Author: Threat Intelligence Pipeline
Version: 1.0.0
"""

import json
import csv
import hashlib
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple
import argparse
import sys

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import scan
except ImportError:
    print("[!] Error: elasticsearch package not installed")
    print("[!] Install: pip install elasticsearch")
    sys.exit(1)


class IOCExtractor:
    """Extracts and analyzes IOCs from honeypot logs"""

    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        """Initialize connection to Elasticsearch"""
        self.es_host = es_host
        self.es_port = es_port

        try:
            self.es = Elasticsearch(
                [f"http://{es_host}:{es_port}"],
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )

            if not self.es.ping():
                raise ConnectionError("Cannot connect to Elasticsearch")

            print(f"[+] Connected to Elasticsearch at {es_host}:{es_port}")

        except Exception as e:
            print(f"[!] Failed to connect to Elasticsearch: {e}")
            sys.exit(1)

    def extract_iocs(self,
                     days_back: int = 7,
                     min_confidence: float = 0.1) -> Dict:
        """
        Extract IOCs from honeypot logs

        Args:
            days_back: Number of days to analyze
            min_confidence: Minimum confidence score (0.0 - 1.0)

        Returns:
            Dictionary containing all extracted IOCs
        """
        print(f"\n[*] Extracting IOCs from last {days_back} days...")

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)

        # Initialize IOC collectors
        iocs = {
            'metadata': {
                'extraction_time': end_time.isoformat(),
                'time_range_start': start_time.isoformat(),
                'time_range_end': end_time.isoformat(),
                'days_analyzed': days_back,
                'min_confidence': min_confidence
            },
            'ips': {},
            'domains': {},
            'urls': {},
            'file_hashes': {},
            'credentials': {},
            'commands': {},
            'malware_families': {},
            'statistics': {}
        }

        # Query honeypot indices
        indices = [
            'honeypot-cowrie-*',
            'honeypot-dionaea-*',
            'honeypot-suricata-*',
            'honeypot-iocs-*'
        ]

        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            }
        }

        total_events = 0

        try:
            # Scan all matching documents
            for index in indices:
                print(f"[*] Processing index: {index}")

                try:
                    results = scan(
                        self.es,
                        query=query,
                        index=index,
                        scroll='5m',
                        size=1000
                    )

                    for doc in results:
                        total_events += 1
                        source = doc['_source']

                        # Extract IPs
                        self._extract_ips(source, iocs)

                        # Extract domains and URLs
                        self._extract_domains_urls(source, iocs)

                        # Extract file hashes
                        self._extract_hashes(source, iocs)

                        # Extract credentials
                        self._extract_credentials(source, iocs)

                        # Extract commands
                        self._extract_commands(source, iocs)

                        # Extract malware families
                        self._extract_malware_families(source, iocs)

                except Exception as e:
                    print(f"[!] Error processing {index}: {e}")
                    continue

            print(f"[+] Processed {total_events:,} events")

            # Calculate confidence scores
            self._calculate_confidence_scores(iocs)

            # Filter by confidence
            iocs = self._filter_by_confidence(iocs, min_confidence)

            # Generate statistics
            iocs['statistics'] = self._generate_statistics(iocs)

            return iocs

        except Exception as e:
            print(f"[!] Error during IOC extraction: {e}")
            return iocs

    def _extract_ips(self, doc: Dict, iocs: Dict):
        """Extract attacker IP addresses"""
        ip_fields = ['attacker_ip', 'src_ip', 'remote_host', 'source_ip']

        for field in ip_fields:
            if field in doc and doc[field]:
                ip = str(doc[field]).strip()

                # Validate IP format
                if self._is_valid_ip(ip):
                    if ip not in iocs['ips']:
                        iocs['ips'][ip] = {
                            'count': 0,
                            'first_seen': doc.get('@timestamp'),
                            'last_seen': doc.get('@timestamp'),
                            'protocols': set(),
                            'honeypots': set(),
                            'threat_score': 0,
                            'geoip': {}
                        }

                    iocs['ips'][ip]['count'] += 1
                    iocs['ips'][ip]['last_seen'] = doc.get('@timestamp')

                    if 'protocol' in doc:
                        iocs['ips'][ip]['protocols'].add(doc['protocol'])

                    if 'honeypot_type' in doc:
                        iocs['ips'][ip]['honeypots'].add(doc['honeypot_type'])

                    if 'threat_score' in doc:
                        iocs['ips'][ip]['threat_score'] = max(
                            iocs['ips'][ip]['threat_score'],
                            doc['threat_score']
                        )

                    # Extract GeoIP data
                    if 'geoip' in doc:
                        iocs['ips'][ip]['geoip'] = {
                            'country': doc['geoip'].get('country_name'),
                            'city': doc['geoip'].get('city_name'),
                            'latitude': doc['geoip'].get('latitude'),
                            'longitude': doc['geoip'].get('longitude'),
                            'asn': doc.get('geoip_asn', {}).get('asn')
                        }

    def _extract_domains_urls(self, doc: Dict, iocs: Dict):
        """Extract domains and URLs"""
        # Extract from specific fields
        if 'extracted_domain' in doc:
            domain = doc['extracted_domain']
            if domain:
                if domain not in iocs['domains']:
                    iocs['domains'][domain] = {
                        'count': 0,
                        'first_seen': doc.get('@timestamp'),
                        'urls': set()
                    }
                iocs['domains'][domain]['count'] += 1

        # Extract URLs
        url_fields = ['http_url', 'file_url', 'extracted_path']
        for field in url_fields:
            if field in doc and doc[field]:
                url = doc[field]
                if url not in iocs['urls']:
                    iocs['urls'][url] = {
                        'count': 0,
                        'first_seen': doc.get('@timestamp'),
                        'method': doc.get('http_method', 'unknown')
                    }
                iocs['urls'][url]['count'] += 1

    def _extract_hashes(self, doc: Dict, iocs: Dict):
        """Extract file hashes (MD5, SHA1, SHA256)"""
        hash_fields = ['file_hash', 'md5_hash', 'sha256_hash', 'sha1_hash']

        for field in hash_fields:
            if field in doc and doc[field]:
                hash_value = str(doc[field]).lower().strip()

                # Determine hash type
                hash_type = 'unknown'
                if len(hash_value) == 32:
                    hash_type = 'md5'
                elif len(hash_value) == 40:
                    hash_type = 'sha1'
                elif len(hash_value) == 64:
                    hash_type = 'sha256'

                if hash_value not in iocs['file_hashes']:
                    iocs['file_hashes'][hash_value] = {
                        'type': hash_type,
                        'count': 0,
                        'first_seen': doc.get('@timestamp'),
                        'filename': doc.get('downloaded_file', 'unknown'),
                        'source_url': doc.get('file_url', '')
                    }
                iocs['file_hashes'][hash_value]['count'] += 1

    def _extract_credentials(self, doc: Dict, iocs: Dict):
        """Extract attempted credentials (username/password pairs)"""
        if 'username_attempted' in doc and 'password_attempted' in doc:
            username = doc['username_attempted']
            password = doc['password_attempted']

            if username and password:
                cred_pair = f"{username}:{password}"

                if cred_pair not in iocs['credentials']:
                    iocs['credentials'][cred_pair] = {
                        'username': username,
                        'password': password,
                        'count': 0,
                        'success': False,
                        'first_seen': doc.get('@timestamp')
                    }

                iocs['credentials'][cred_pair]['count'] += 1

                if 'cowrie.login.success' in doc.get('auth_result', ''):
                    iocs['credentials'][cred_pair]['success'] = True

    def _extract_commands(self, doc: Dict, iocs: Dict):
        """Extract executed commands"""
        if 'command_executed' in doc:
            command = doc['command_executed']

            if command:
                if command not in iocs['commands']:
                    iocs['commands'][command] = {
                        'count': 0,
                        'first_seen': doc.get('@timestamp'),
                        'mitre_technique': doc.get('mitre_technique', 'unknown')
                    }
                iocs['commands'][command]['count'] += 1

    def _extract_malware_families(self, doc: Dict, iocs: Dict):
        """Extract malware family indicators"""
        # Look for common malware signatures in commands/URLs
        malware_patterns = {
            'mirai': r'mirai|\/bin\/busybox',
            'xmrig': r'xmrig|cryptonight|monero',
            'gafgyt': r'gafgyt|bashlite',
            'emotet': r'emotet|epoch[0-9]',
            'wannacry': r'wannacry|wcry',
            'cobalt_strike': r'beacon|cobaltstrike',
        }

        text_to_check = ' '.join([
            str(doc.get('command_executed', '')),
            str(doc.get('http_url', '')),
            str(doc.get('file_url', ''))
        ]).lower()

        for family, pattern in malware_patterns.items():
            if re.search(pattern, text_to_check):
                if family not in iocs['malware_families']:
                    iocs['malware_families'][family] = {
                        'count': 0,
                        'first_seen': doc.get('@timestamp')
                    }
                iocs['malware_families'][family]['count'] += 1

    def _calculate_confidence_scores(self, iocs: Dict):
        """Calculate confidence scores for IOCs (0.0 - 1.0)"""
        # IP confidence based on frequency and diversity
        if iocs['ips']:
            max_ip_count = max(ip['count'] for ip in iocs['ips'].values())

            for ip, data in iocs['ips'].items():
                # Base confidence on frequency
                freq_score = min(data['count'] / max(max_ip_count, 1), 1.0)

                # Boost if multiple protocols
                protocol_score = len(data['protocols']) * 0.1

                # Boost if high threat score
                threat_score = min(data.get('threat_score', 0) / 100, 1.0)

                # Combined confidence
                data['confidence'] = min((freq_score * 0.5) +
                                        (protocol_score * 0.2) +
                                        (threat_score * 0.3), 1.0)

        # Hash confidence (any malware sample is high confidence)
        for hash_value, data in iocs['file_hashes'].items():
            data['confidence'] = 0.9  # High confidence for file downloads

        # Credential confidence
        if iocs['credentials']:
            max_cred_count = max(c['count'] for c in iocs['credentials'].values())

            for cred, data in iocs['credentials'].items():
                data['confidence'] = min(data['count'] / max(max_cred_count, 1), 1.0)

        # Domain/URL confidence
        for url, data in iocs['urls'].items():
            data['confidence'] = 0.7  # Medium-high confidence

        for domain, data in iocs['domains'].items():
            data['confidence'] = 0.7

    def _filter_by_confidence(self, iocs: Dict, min_confidence: float) -> Dict:
        """Filter IOCs by minimum confidence score"""
        filtered = iocs.copy()

        for ioc_type in ['ips', 'domains', 'urls', 'file_hashes', 'credentials']:
            if ioc_type in filtered:
                filtered[ioc_type] = {
                    k: v for k, v in filtered[ioc_type].items()
                    if v.get('confidence', 0) >= min_confidence
                }

        return filtered

    def _generate_statistics(self, iocs: Dict) -> Dict:
        """Generate summary statistics"""
        return {
            'total_unique_ips': len(iocs['ips']),
            'total_unique_domains': len(iocs['domains']),
            'total_unique_urls': len(iocs['urls']),
            'total_file_hashes': len(iocs['file_hashes']),
            'total_credentials': len(iocs['credentials']),
            'total_commands': len(iocs['commands']),
            'total_malware_families': len(iocs['malware_families']),
            'top_attacker_ips': self._get_top_items(iocs['ips'], 10),
            'top_credentials': self._get_top_items(iocs['credentials'], 10),
            'top_commands': self._get_top_items(iocs['commands'], 10)
        }

    def _get_top_items(self, items: Dict, limit: int = 10) -> List[Tuple]:
        """Get top N items by count"""
        sorted_items = sorted(
            items.items(),
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )
        return [(k, v['count']) for k, v in sorted_items[:limit]]

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False

    def export_json(self, iocs: Dict, output_file: str):
        """Export IOCs to JSON format"""
        print(f"[*] Exporting to JSON: {output_file}")

        # Convert sets to lists for JSON serialization
        iocs_json = self._prepare_for_json(iocs)

        with open(output_file, 'w') as f:
            json.dump(iocs_json, f, indent=2, default=str)

        print(f"[+] JSON export complete")

    def export_csv(self, iocs: Dict, output_file: str):
        """Export IOCs to CSV format (for SIEM ingestion)"""
        print(f"[*] Exporting to CSV: {output_file}")

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow([
                'IOC_Type', 'IOC_Value', 'Confidence', 'Count',
                'First_Seen', 'Additional_Info'
            ])

            # Write IPs
            for ip, data in iocs['ips'].items():
                writer.writerow([
                    'IP',
                    ip,
                    f"{data['confidence']:.2f}",
                    data['count'],
                    data['first_seen'],
                    f"Country: {data['geoip'].get('country', 'Unknown')}"
                ])

            # Write hashes
            for hash_val, data in iocs['file_hashes'].items():
                writer.writerow([
                    f'Hash_{data["type"].upper()}',
                    hash_val,
                    f"{data['confidence']:.2f}",
                    data['count'],
                    data['first_seen'],
                    f"File: {data['filename']}"
                ])

            # Write domains
            for domain, data in iocs['domains'].items():
                writer.writerow([
                    'Domain',
                    domain,
                    f"{data['confidence']:.2f}",
                    data['count'],
                    data['first_seen'],
                    ''
                ])

        print(f"[+] CSV export complete")

    def export_markdown(self, iocs: Dict, output_file: str):
        """Export IOCs to Markdown report format"""
        print(f"[*] Exporting to Markdown: {output_file}")

        with open(output_file, 'w') as f:
            f.write("# Threat Intelligence Report - IOC Summary\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

            # Executive summary
            f.write("## Executive Summary\n\n")
            stats = iocs['statistics']
            f.write(f"- **Unique Attacker IPs:** {stats['total_unique_ips']:,}\n")
            f.write(f"- **Malware Samples:** {stats['total_file_hashes']:,}\n")
            f.write(f"- **Credentials Attempted:** {stats['total_credentials']:,}\n")
            f.write(f"- **Commands Executed:** {stats['total_commands']:,}\n")
            f.write(f"- **Malware Families:** {stats['total_malware_families']:,}\n\n")

            # Top attackers
            f.write("## Top 10 Attacker IPs\n\n")
            f.write("| Rank | IP Address | Attack Count | Country |\n")
            f.write("|------|------------|--------------|----------|\n")

            for idx, (ip, count) in enumerate(stats['top_attacker_ips'], 1):
                country = iocs['ips'][ip]['geoip'].get('country', 'Unknown')
                f.write(f"| {idx} | `{ip}` | {count:,} | {country} |\n")

            # Top credentials
            f.write("\n## Top 10 Credentials Attempted\n\n")
            f.write("| Rank | Credential | Attempt Count |\n")
            f.write("|------|------------|---------------|\n")

            for idx, (cred, count) in enumerate(stats['top_credentials'], 1):
                f.write(f"| {idx} | `{cred}` | {count:,} |\n")

            # Malware hashes
            f.write("\n## Malware Samples (Hashes)\n\n")
            f.write("| Hash Type | Hash Value | Count |\n")
            f.write("|-----------|------------|-------|\n")

            for hash_val, data in list(iocs['file_hashes'].items())[:20]:
                f.write(f"| {data['type'].upper()} | `{hash_val}` | {data['count']} |\n")

        print(f"[+] Markdown export complete")

    def _prepare_for_json(self, obj):
        """Convert sets to lists for JSON serialization"""
        if isinstance(obj, dict):
            return {k: self._prepare_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, list):
            return [self._prepare_for_json(item) for item in obj]
        else:
            return obj


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Extract IOCs from honeypot logs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--es-host',
        default='localhost',
        help='Elasticsearch host (default: localhost)'
    )

    parser.add_argument(
        '--es-port',
        type=int,
        default=9200,
        help='Elasticsearch port (default: 9200)'
    )

    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Days of data to analyze (default: 7)'
    )

    parser.add_argument(
        '--confidence',
        type=float,
        default=0.1,
        help='Minimum confidence score 0.0-1.0 (default: 0.1)'
    )

    parser.add_argument(
        '--output-json',
        default='iocs.json',
        help='JSON output file (default: iocs.json)'
    )

    parser.add_argument(
        '--output-csv',
        default='iocs.csv',
        help='CSV output file (default: iocs.csv)'
    )

    parser.add_argument(
        '--output-md',
        default='iocs_report.md',
        help='Markdown output file (default: iocs_report.md)'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("IOC EXTRACTION ENGINE")
    print("=" * 60)

    # Initialize extractor
    extractor = IOCExtractor(args.es_host, args.es_port)

    # Extract IOCs
    iocs = extractor.extract_iocs(args.days, args.confidence)

    # Export to multiple formats
    extractor.export_json(iocs, args.output_json)
    extractor.export_csv(iocs, args.output_csv)
    extractor.export_markdown(iocs, args.output_md)

    # Print summary
    print("\n" + "=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Unique IPs: {iocs['statistics']['total_unique_ips']:,}")
    print(f"File Hashes: {iocs['statistics']['total_file_hashes']:,}")
    print(f"Credentials: {iocs['statistics']['total_credentials']:,}")
    print(f"Commands: {iocs['statistics']['total_commands']:,}")
    print(f"Malware Families: {iocs['statistics']['total_malware_families']:,}")
    print("=" * 60)


if __name__ == '__main__':
    main()
