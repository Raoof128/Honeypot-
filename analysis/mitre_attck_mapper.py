#!/usr/bin/env python3
"""
MITRE ATT&CK Framework Mapper for Honeypot Attacks
Maps observed honeypot activity to MITRE ATT&CK techniques and tactics

Features:
- Automatic technique classification
- Tactic frequency analysis
- ATT&CK Navigator layer generation
- TTP (Tactics, Techniques, Procedures) timeline
- Threat actor profiling

Author: Threat Intelligence Pipeline
Version: 1.0.0
"""

import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Set
import argparse
import sys

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import scan
except ImportError:
    print("[!] Error: elasticsearch package not installed")
    print("[!] Install: pip install elasticsearch")
    sys.exit(1)


# MITRE ATT&CK Technique Mappings
ATTACK_TECHNIQUES = {
    # Initial Access
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'description': 'Exploitation of web servers, databases, or other internet-facing services',
        'patterns': [r'\.php', r'\.asp', r'cgi-bin', r'/admin', r'phpmyadmin', r'wp-admin',
                    r'sql injection', r'xss', r'<script', r'union select']
    },
    'T1133': {
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
        'description': 'Use of external remote services like SSH, RDP, VPN',
        'patterns': [r'ssh', r'rdp', r'vpn']
    },
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'Initial Access',
        'description': 'Use of legitimate credentials',
        'patterns': [r'login.*success', r'authentication.*success']
    },

    # Execution
    'T1059.001': {
        'name': 'Command and Scripting Interpreter: PowerShell',
        'tactic': 'Execution',
        'description': 'Use of PowerShell for execution',
        'patterns': [r'powershell', r'\.ps1', r'invoke-', r'iex']
    },
    'T1059.004': {
        'name': 'Command and Scripting Interpreter: Unix Shell',
        'tactic': 'Execution',
        'description': 'Use of Unix/Linux shell commands',
        'patterns': [r'/bin/bash', r'/bin/sh', r'bash -c', r'sh -c', r'export']
    },
    'T1059.006': {
        'name': 'Command and Scripting Interpreter: Python',
        'tactic': 'Execution',
        'description': 'Use of Python for execution',
        'patterns': [r'python', r'\.py ', r'import os', r'import socket']
    },
    'T1059.007': {
        'name': 'Command and Scripting Interpreter: JavaScript',
        'tactic': 'Execution',
        'description': 'Use of JavaScript for execution',
        'patterns': [r'<script', r'javascript:', r'eval\(', r'\.js']
    },

    # Persistence
    'T1543': {
        'name': 'Create or Modify System Process',
        'tactic': 'Persistence',
        'description': 'Creation of services or daemons for persistence',
        'patterns': [r'systemctl', r'service ', r'chkconfig', r'/etc/init\.d']
    },
    'T1053': {
        'name': 'Scheduled Task/Job',
        'tactic': 'Persistence',
        'description': 'Use of cron, at, or scheduled tasks',
        'patterns': [r'crontab', r'at ', r'/etc/cron', r'schtasks']
    },
    'T1098': {
        'name': 'Account Manipulation',
        'tactic': 'Persistence',
        'description': 'Creating or modifying user accounts',
        'patterns': [r'useradd', r'adduser', r'passwd ', r'usermod']
    },

    # Privilege Escalation
    'T1548': {
        'name': 'Abuse Elevation Control Mechanism',
        'tactic': 'Privilege Escalation',
        'description': 'Use of sudo, setuid, or similar mechanisms',
        'patterns': [r'sudo ', r'su ', r'chmod \+s', r'setuid', r'pkexec']
    },
    'T1068': {
        'name': 'Exploitation for Privilege Escalation',
        'tactic': 'Privilege Escalation',
        'description': 'Kernel exploits or privilege escalation exploits',
        'patterns': [r'exploit', r'dirty.*cow', r'privilege.*escalation']
    },

    # Defense Evasion
    'T1070.006': {
        'name': 'Indicator Removal: Clear Command History',
        'tactic': 'Defense Evasion',
        'description': 'Clearing command history',
        'patterns': [r'history -c', r'rm.*\.bash_history', r'unset HISTFILE']
    },
    'T1070.001': {
        'name': 'Indicator Removal: Clear Linux or Mac System Logs',
        'tactic': 'Defense Evasion',
        'description': 'Clearing system logs',
        'patterns': [r'rm.*\/var\/log', r'echo.*>.*log', r'truncate.*log']
    },
    'T1027': {
        'name': 'Obfuscated Files or Information',
        'tactic': 'Defense Evasion',
        'description': 'Use of encoding or obfuscation',
        'patterns': [r'base64', r'uuencode', r'xxd', r'openssl enc']
    },

    # Credential Access
    'T1110.001': {
        'name': 'Brute Force: Password Guessing',
        'tactic': 'Credential Access',
        'description': 'Attempting multiple passwords',
        'patterns': [r'login.*failed', r'authentication.*failed', r'invalid.*password']
    },
    'T1110.003': {
        'name': 'Brute Force: Password Spraying',
        'tactic': 'Credential Access',
        'description': 'Trying common passwords across many accounts',
        'patterns': [r'admin:admin', r'root:root', r'admin:123456']
    },
    'T1003': {
        'name': 'OS Credential Dumping',
        'tactic': 'Credential Access',
        'description': 'Dumping credentials from OS',
        'patterns': [r'/etc/passwd', r'/etc/shadow', r'mimikatz', r'hashdump']
    },

    # Discovery
    'T1083': {
        'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
        'description': 'Listing files and directories',
        'patterns': [r'\bls\b', r'\bdir\b', r'find /', r'locate ', r'tree ']
    },
    'T1082': {
        'name': 'System Information Discovery',
        'tactic': 'Discovery',
        'description': 'Gathering system information',
        'patterns': [r'uname', r'hostname', r'whoami', r'id\b', r'cat /proc', r'systeminfo']
    },
    'T1016': {
        'name': 'System Network Configuration Discovery',
        'tactic': 'Discovery',
        'description': 'Network configuration enumeration',
        'patterns': [r'ifconfig', r'ip addr', r'route', r'netstat', r'arp']
    },
    'T1057': {
        'name': 'Process Discovery',
        'tactic': 'Discovery',
        'description': 'Listing running processes',
        'patterns': [r'\bps\b', r'top\b', r'tasklist']
    },

    # Lateral Movement
    'T1021.004': {
        'name': 'Remote Services: SSH',
        'tactic': 'Lateral Movement',
        'description': 'Use of SSH for lateral movement',
        'patterns': [r'ssh ', r'scp ', r'sftp']
    },
    'T1021.002': {
        'name': 'Remote Services: SMB/Windows Admin Shares',
        'tactic': 'Lateral Movement',
        'description': 'Use of SMB for lateral movement',
        'patterns': [r'smb', r'\\\\C\$', r'net use', r'psexec']
    },

    # Collection
    'T1560': {
        'name': 'Archive Collected Data',
        'tactic': 'Collection',
        'description': 'Archiving data for exfiltration',
        'patterns': [r'\btar\b', r'\bzip\b', r'gzip', r'7z', r'rar']
    },

    # Command and Control
    'T1071.001': {
        'name': 'Application Layer Protocol: Web Protocols',
        'tactic': 'Command and Control',
        'description': 'Use of HTTP/HTTPS for C2',
        'patterns': [r'wget', r'curl', r'fetch', r'http://', r'https://']
    },
    'T1571': {
        'name': 'Non-Standard Port',
        'tactic': 'Command and Control',
        'description': 'C2 over non-standard ports',
        'patterns': [r'nc ', r'netcat', r'ncat']
    },
    'T1105': {
        'name': 'Ingress Tool Transfer',
        'tactic': 'Command and Control',
        'description': 'Downloading tools or malware',
        'patterns': [r'wget http', r'curl.*-O', r'fetch.*http', r'tftp']
    },

    # Exfiltration
    'T1041': {
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
        'description': 'Data exfiltration over C2',
        'patterns': [r'curl.*--data', r'wget.*--post']
    },

    # Impact
    'T1485': {
        'name': 'Data Destruction',
        'tactic': 'Impact',
        'description': 'Destructive commands',
        'patterns': [r'rm -rf', r'dd if=/dev/zero', r'mkfs', r'shred']
    },
    'T1496': {
        'name': 'Resource Hijacking',
        'tactic': 'Impact',
        'description': 'Cryptocurrency mining',
        'patterns': [r'xmrig', r'minerd', r'cryptonight', r'monero', r'stratum']
    },
    'T1489': {
        'name': 'Service Stop',
        'tactic': 'Impact',
        'description': 'Stopping services',
        'patterns': [r'systemctl stop', r'service.*stop', r'kill ']
    }
}


class MITREAttackMapper:
    """Maps honeypot activity to MITRE ATT&CK framework"""

    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        """Initialize MITRE ATT&CK mapper"""
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

    def analyze_ttps(self, days_back: int = 7) -> Dict:
        """
        Analyze Tactics, Techniques, and Procedures from honeypot logs

        Args:
            days_back: Number of days to analyze

        Returns:
            TTP analysis results
        """
        print(f"\n[*] Analyzing TTPs (last {days_back} days)...")

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)

        # Initialize collectors
        ttp_data = {
            'metadata': {
                'analysis_time': end_time.isoformat(),
                'time_range_start': start_time.isoformat(),
                'time_range_end': end_time.isoformat(),
                'days_analyzed': days_back
            },
            'techniques': defaultdict(lambda: {
                'count': 0,
                'name': '',
                'tactic': '',
                'description': '',
                'examples': [],
                'first_seen': None,
                'last_seen': None,
                'attacker_ips': set()
            }),
            'tactics': defaultdict(int),
            'timeline': [],
            'statistics': {}
        }

        # Query logs
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}]
        }

        indices = ['honeypot-*']
        total_events = 0

        try:
            results = scan(
                self.es,
                query=query,
                index=indices,
                scroll='5m',
                size=1000
            )

            for doc in results:
                total_events += 1
                source = doc['_source']

                # Check for existing MITRE technique tag
                existing_technique = source.get('mitre_technique')

                if existing_technique:
                    self._record_technique(
                        existing_technique,
                        source,
                        ttp_data
                    )

                # Pattern-based detection
                self._detect_techniques_by_pattern(source, ttp_data)

            print(f"[+] Processed {total_events:,} events")

            # Generate statistics
            ttp_data['statistics'] = self._generate_ttp_statistics(ttp_data)

            # Convert sets to lists
            ttp_data = self._prepare_for_export(ttp_data)

            return ttp_data

        except Exception as e:
            print(f"[!] Error during TTP analysis: {e}")
            import traceback
            traceback.print_exc()
            return ttp_data

    def _detect_techniques_by_pattern(self, doc: Dict, ttp_data: Dict):
        """Detect MITRE techniques by pattern matching"""
        # Get searchable text from document
        searchable_fields = [
            doc.get('command_executed', ''),
            doc.get('http_url', ''),
            doc.get('file_url', ''),
            doc.get('alert_signature', ''),
            str(doc.get('username_attempted', '')),
            str(doc.get('password_attempted', ''))
        ]

        search_text = ' '.join(searchable_fields).lower()

        # Match against technique patterns
        for technique_id, technique_info in ATTACK_TECHNIQUES.items():
            for pattern in technique_info['patterns']:
                if re.search(pattern, search_text, re.IGNORECASE):
                    self._record_technique(technique_id, doc, ttp_data)
                    break

    def _record_technique(self, technique_id: str, doc: Dict, ttp_data: Dict):
        """Record a detected technique"""
        if technique_id not in ATTACK_TECHNIQUES:
            return

        technique = ttp_data['techniques'][technique_id]
        technique_info = ATTACK_TECHNIQUES[technique_id]

        # Initialize if first occurrence
        if technique['count'] == 0:
            technique['name'] = technique_info['name']
            technique['tactic'] = technique_info['tactic']
            technique['description'] = technique_info['description']
            technique['first_seen'] = doc.get('@timestamp')

        # Update
        technique['count'] += 1
        technique['last_seen'] = doc.get('@timestamp')

        # Add example (limit to 5)
        if len(technique['examples']) < 5:
            example = {
                'timestamp': doc.get('@timestamp'),
                'command': doc.get('command_executed', ''),
                'source_ip': doc.get('attacker_ip', ''),
                'honeypot': doc.get('honeypot_type', '')
            }
            technique['examples'].append(example)

        # Track attacker IPs
        if 'attacker_ip' in doc:
            technique['attacker_ips'].add(doc['attacker_ip'])

        # Increment tactic counter
        tactic = technique_info['tactic']
        ttp_data['tactics'][tactic] += 1

        # Add to timeline
        ttp_data['timeline'].append({
            'timestamp': doc.get('@timestamp'),
            'technique_id': technique_id,
            'technique_name': technique_info['name'],
            'tactic': tactic
        })

    def _generate_ttp_statistics(self, ttp_data: Dict) -> Dict:
        """Generate TTP statistics"""
        techniques = ttp_data['techniques']
        tactics = ttp_data['tactics']

        # Top 10 techniques
        top_techniques = sorted(
            [(tid, data['count'], data['name']) for tid, data in techniques.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Tactic distribution
        tactic_distribution = sorted(
            tactics.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return {
            'total_techniques_observed': len(techniques),
            'total_tactics_observed': len(tactics),
            'total_technique_occurrences': sum(t['count'] for t in techniques.values()),
            'top_techniques': top_techniques,
            'tactic_distribution': tactic_distribution,
            'most_common_tactic': tactic_distribution[0][0] if tactic_distribution else None
        }

    def _prepare_for_export(self, ttp_data: Dict) -> Dict:
        """Convert sets to lists for JSON export"""
        result = ttp_data.copy()

        for technique_id, data in result['techniques'].items():
            if isinstance(data['attacker_ips'], set):
                data['attacker_ips'] = list(data['attacker_ips'])

        return result

    def export_json(self, ttp_data: Dict, output_file: str):
        """Export TTP data to JSON"""
        print(f"[*] Exporting to JSON: {output_file}")

        with open(output_file, 'w') as f:
            json.dump(ttp_data, f, indent=2, default=str)

        print(f"[+] JSON export complete")

    def export_attack_navigator(self, ttp_data: Dict, output_file: str):
        """Export ATT&CK Navigator layer"""
        print(f"[*] Generating ATT&CK Navigator layer: {output_file}")

        # Calculate max count for scoring
        max_count = max(
            (t['count'] for t in ttp_data['techniques'].values()),
            default=1
        )

        # Generate layer
        layer = {
            "name": "Honeypot Observed Techniques",
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK techniques observed in honeypot (last {ttp_data['metadata']['days_analyzed']} days)",
            "filters": {
                "platforms": ["linux", "windows", "network"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": []
        }

        # Add techniques
        for technique_id, data in ttp_data['techniques'].items():
            # Normalize score (0-100)
            score = int((data['count'] / max_count) * 100)

            # Color based on frequency
            if score >= 75:
                color = "#ff6666"  # Red
            elif score >= 50:
                color = "#ffaa00"  # Orange
            elif score >= 25:
                color = "#ffdd00"  # Yellow
            else:
                color = "#77ff77"  # Green

            layer['techniques'].append({
                "techniqueID": technique_id,
                "tactic": data['tactic'].lower().replace(' ', '-'),
                "score": score,
                "color": color,
                "comment": f"Observed {data['count']} times",
                "enabled": True,
                "metadata": [
                    {"name": "Occurrences", "value": str(data['count'])},
                    {"name": "Unique IPs", "value": str(len(data['attacker_ips']))}
                ]
            })

        with open(output_file, 'w') as f:
            json.dump(layer, f, indent=2)

        print(f"[+] ATT&CK Navigator layer generated")
        print(f"[+] Upload to: https://mitre-attack.github.io/attack-navigator/")

    def export_markdown_report(self, ttp_data: Dict, output_file: str):
        """Export TTP analysis as Markdown report"""
        print(f"[*] Generating Markdown report: {output_file}")

        stats = ttp_data['statistics']

        with open(output_file, 'w') as f:
            f.write("# MITRE ATT&CK TTP Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

            # Executive summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Techniques Observed:** {stats['total_techniques_observed']}\n")
            f.write(f"- **Tactics Observed:** {stats['total_tactics_observed']}\n")
            f.write(f"- **Total Occurrences:** {stats['total_technique_occurrences']:,}\n")
            f.write(f"- **Most Common Tactic:** {stats['most_common_tactic']}\n\n")

            # Top techniques
            f.write("## Top 10 Observed Techniques\n\n")
            f.write("| Rank | Technique ID | Name | Count |\n")
            f.write("|------|--------------|------|-------|\n")

            for idx, (tid, count, name) in enumerate(stats['top_techniques'], 1):
                f.write(f"| {idx} | `{tid}` | {name} | {count:,} |\n")

            # Tactic distribution
            f.write("\n## Tactic Distribution\n\n")
            f.write("| Tactic | Occurrences |\n")
            f.write("|--------|-------------|\n")

            for tactic, count in stats['tactic_distribution']:
                f.write(f"| {tactic} | {count:,} |\n")

            # Detailed technique breakdown
            f.write("\n## Detailed Technique Analysis\n\n")

            for technique_id, data in sorted(
                ttp_data['techniques'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            ):
                f.write(f"### {technique_id}: {data['name']}\n\n")
                f.write(f"- **Tactic:** {data['tactic']}\n")
                f.write(f"- **Count:** {data['count']:,}\n")
                f.write(f"- **Unique Attacker IPs:** {len(data['attacker_ips'])}\n")
                f.write(f"- **First Seen:** {data['first_seen']}\n")
                f.write(f"- **Last Seen:** {data['last_seen']}\n\n")

                if data['examples']:
                    f.write("**Examples:**\n\n")
                    for example in data['examples'][:3]:
                        if example['command']:
                            f.write(f"- `{example['command']}` (from {example['source_ip']})\n")

                f.write("\n")

        print(f"[+] Markdown report generated")


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Map honeypot activity to MITRE ATT&CK framework'
    )

    parser.add_argument('--es-host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--es-port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--days', type=int, default=7, help='Days to analyze')
    parser.add_argument('--output-json', default='mitre_analysis.json',
                        help='JSON output file')
    parser.add_argument('--output-navigator', default='attack_navigator.json',
                        help='ATT&CK Navigator layer file')
    parser.add_argument('--output-report', default='mitre_report.md',
                        help='Markdown report file')

    args = parser.parse_args()

    print("=" * 60)
    print("MITRE ATT&CK TTP ANALYSIS ENGINE")
    print("=" * 60)

    # Initialize mapper
    mapper = MITREAttackMapper(args.es_host, args.es_port)

    # Analyze TTPs
    ttp_data = mapper.analyze_ttps(args.days)

    # Export results
    mapper.export_json(ttp_data, args.output_json)
    mapper.export_attack_navigator(ttp_data, args.output_navigator)
    mapper.export_markdown_report(ttp_data, args.output_report)

    # Print summary
    print("\n" + "=" * 60)
    print("TTP ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Techniques: {ttp_data['statistics']['total_techniques_observed']}")
    print(f"Tactics: {ttp_data['statistics']['total_tactics_observed']}")
    print(f"Total Occurrences: {ttp_data['statistics']['total_technique_occurrences']:,}")
    print("=" * 60)


if __name__ == '__main__':
    main()
