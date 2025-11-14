#!/usr/bin/env python3
"""
Geolocation Mapping & Analysis for Honeypot Threat Intelligence
Maps attacker IPs to geographic locations and generates heat maps

Features:
- GeoIP lookup using MaxMind GeoLite2
- Country/city distribution analysis
- Attack corridor identification
- Geographic heat map data generation
- Time-based geographic trending

Author: Threat Intelligence Pipeline
Version: 1.0.0
"""

import json
import csv
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple
import argparse
import sys

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import scan
except ImportError:
    print("[!] Error: elasticsearch package not installed")
    print("[!] Install: pip install elasticsearch")
    sys.exit(1)

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    print("[!] Error: geoip2 package not installed")
    print("[!] Install: pip install geoip2")
    sys.exit(1)


class GeolocationMapper:
    """Maps attacker IPs to geographic locations"""

    def __init__(self,
                 es_host: str = "localhost",
                 es_port: int = 9200,
                 geoip_db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"):
        """
        Initialize geolocation mapper

        Args:
            es_host: Elasticsearch host
            es_port: Elasticsearch port
            geoip_db_path: Path to MaxMind GeoLite2 database
        """
        self.es_host = es_host
        self.es_port = es_port

        # Connect to Elasticsearch
        try:
            self.es = Elasticsearch(
                [f"http://{es_host}:{es_port}"],
                timeout=30,
                max_retries=3
            )

            if not self.es.ping():
                raise ConnectionError("Cannot connect to Elasticsearch")

            print(f"[+] Connected to Elasticsearch at {es_host}:{es_port}")

        except Exception as e:
            print(f"[!] Failed to connect to Elasticsearch: {e}")
            sys.exit(1)

        # Load GeoIP database
        try:
            self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            print(f"[+] Loaded GeoIP database: {geoip_db_path}")

        except FileNotFoundError:
            print(f"[!] GeoIP database not found: {geoip_db_path}")
            print("[!] Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            print("[!] Or install: apt-get install geoip-database-contrib")
            self.geoip_reader = None

    def analyze_geographic_distribution(self, days_back: int = 7) -> Dict:
        """
        Analyze geographic distribution of attacks

        Args:
            days_back: Number of days to analyze

        Returns:
            Geographic analysis results
        """
        print(f"\n[*] Analyzing geographic distribution (last {days_back} days)...")

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)

        # Initialize collectors
        geo_data = {
            'metadata': {
                'analysis_time': end_time.isoformat(),
                'time_range_start': start_time.isoformat(),
                'time_range_end': end_time.isoformat(),
                'days_analyzed': days_back
            },
            'countries': defaultdict(lambda: {
                'count': 0,
                'unique_ips': set(),
                'cities': defaultdict(int),
                'attack_types': defaultdict(int),
                'first_seen': None,
                'last_seen': None
            }),
            'cities': defaultdict(lambda: {
                'count': 0,
                'country': '',
                'latitude': 0,
                'longitude': 0,
                'unique_ips': set()
            }),
            'coordinates': [],  # For heat map
            'attack_corridors': {},  # Persistent attack sources
            'statistics': {}
        }

        # Query honeypot logs
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}},
                        {"exists": {"field": "attacker_ip"}}
                    ]
                }
            }
        }

        indices = ['honeypot-*']
        total_events = 0
        processed_ips = set()

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

                attacker_ip = source.get('attacker_ip')
                if not attacker_ip:
                    continue

                timestamp = source.get('@timestamp')
                attack_type = source.get('honeypot_type', 'unknown')

                # GeoIP lookup
                geo_info = self._geoip_lookup(attacker_ip)

                if geo_info:
                    country = geo_info['country']
                    city = geo_info['city']
                    lat = geo_info['latitude']
                    lon = geo_info['longitude']

                    # Update country data
                    geo_data['countries'][country]['count'] += 1
                    geo_data['countries'][country]['unique_ips'].add(attacker_ip)
                    geo_data['countries'][country]['cities'][city] += 1
                    geo_data['countries'][country]['attack_types'][attack_type] += 1

                    if not geo_data['countries'][country]['first_seen']:
                        geo_data['countries'][country]['first_seen'] = timestamp
                    geo_data['countries'][country]['last_seen'] = timestamp

                    # Update city data
                    city_key = f"{city}, {country}"
                    geo_data['cities'][city_key]['count'] += 1
                    geo_data['cities'][city_key]['country'] = country
                    geo_data['cities'][city_key]['latitude'] = lat
                    geo_data['cities'][city_key]['longitude'] = lon
                    geo_data['cities'][city_key]['unique_ips'].add(attacker_ip)

                    # Add coordinate for heat map
                    if lat and lon:
                        geo_data['coordinates'].append({
                            'lat': lat,
                            'lon': lon,
                            'count': 1,
                            'ip': attacker_ip,
                            'country': country,
                            'city': city
                        })

                    processed_ips.add(attacker_ip)

            print(f"[+] Processed {total_events:,} events from {len(processed_ips):,} unique IPs")

            # Identify attack corridors (countries with sustained attacks)
            geo_data['attack_corridors'] = self._identify_attack_corridors(
                geo_data['countries']
            )

            # Generate statistics
            geo_data['statistics'] = self._generate_geo_statistics(geo_data)

            # Convert sets to lists for JSON serialization
            geo_data = self._prepare_for_export(geo_data)

            return geo_data

        except Exception as e:
            print(f"[!] Error during geographic analysis: {e}")
            import traceback
            traceback.print_exc()
            return geo_data

    def _geoip_lookup(self, ip: str) -> Dict:
        """
        Perform GeoIP lookup for an IP address

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with geographic information
        """
        if not self.geoip_reader:
            return None

        try:
            response = self.geoip_reader.city(ip)

            return {
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX',
                'city': response.city.name or 'Unknown',
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'postal_code': response.postal.code
            }

        except geoip2.errors.AddressNotFoundError:
            return {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0,
                'timezone': None,
                'postal_code': None
            }

        except Exception as e:
            print(f"[!] GeoIP lookup error for {ip}: {e}")
            return None

    def _identify_attack_corridors(self, countries: Dict) -> Dict:
        """
        Identify attack corridors (persistent attack sources)

        Criteria:
        - High attack volume (top 20%)
        - Multiple unique IPs
        - Sustained over time
        """
        corridors = {}

        if not countries:
            return corridors

        # Calculate threshold (top 20% by volume)
        all_counts = [data['count'] for data in countries.values()]
        threshold = sorted(all_counts, reverse=True)[int(len(all_counts) * 0.2)] if all_counts else 0

        for country, data in countries.items():
            if data['count'] >= threshold and len(data['unique_ips']) >= 5:
                corridors[country] = {
                    'total_attacks': data['count'],
                    'unique_ips': len(data['unique_ips']),
                    'top_cities': sorted(
                        data['cities'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5],
                    'attack_types': dict(data['attack_types']),
                    'threat_level': self._calculate_threat_level(data)
                }

        return corridors

    def _calculate_threat_level(self, country_data: Dict) -> str:
        """Calculate threat level for a country"""
        attack_count = country_data['count']
        unique_ips = len(country_data['unique_ips'])

        # High: >1000 attacks or >50 unique IPs
        if attack_count > 1000 or unique_ips > 50:
            return 'HIGH'
        # Medium: >100 attacks or >10 unique IPs
        elif attack_count > 100 or unique_ips > 10:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_geo_statistics(self, geo_data: Dict) -> Dict:
        """Generate geographic statistics"""
        countries = geo_data['countries']
        cities = geo_data['cities']

        # Top 10 countries by attack volume
        top_countries = sorted(
            [(country, data['count']) for country, data in countries.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Top 10 cities
        top_cities = sorted(
            [(city, data['count']) for city, data in cities.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Calculate diversity metrics
        total_attacks = sum(data['count'] for data in countries.values())
        unique_countries = len(countries)
        unique_cities = len(cities)

        return {
            'total_attacks': total_attacks,
            'unique_countries': unique_countries,
            'unique_cities': unique_cities,
            'top_countries': top_countries,
            'top_cities': top_cities,
            'attack_corridors_count': len(geo_data['attack_corridors']),
            'geographic_diversity_score': min(unique_countries / 50, 1.0)  # Normalized
        }

    def _prepare_for_export(self, geo_data: Dict) -> Dict:
        """Convert sets to lists for JSON export"""
        result = {}

        for key, value in geo_data.items():
            if isinstance(value, dict):
                result[key] = {}
                for k, v in value.items():
                    if isinstance(v, dict):
                        result[key][k] = {
                            sub_k: list(sub_v) if isinstance(sub_v, set) else sub_v
                            for sub_k, sub_v in v.items()
                        }
                    else:
                        result[key][k] = list(v) if isinstance(v, set) else v
            else:
                result[key] = value

        return result

    def export_json(self, geo_data: Dict, output_file: str):
        """Export geographic data to JSON"""
        print(f"[*] Exporting to JSON: {output_file}")

        with open(output_file, 'w') as f:
            json.dump(geo_data, f, indent=2, default=str)

        print(f"[+] JSON export complete")

    def export_heatmap_html(self, geo_data: Dict, output_file: str):
        """Export interactive HTML heat map"""
        print(f"[*] Generating heat map: {output_file}")

        # Aggregate coordinates
        coord_counts = defaultdict(int)
        coord_info = {}

        for coord in geo_data['coordinates']:
            key = (coord['lat'], coord['lon'])
            coord_counts[key] += 1
            if key not in coord_info:
                coord_info[key] = {
                    'country': coord['country'],
                    'city': coord['city']
                }

        # Generate HTML with Leaflet.js
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Attack Heat Map</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.css" />
    <style>
        body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; }}
        #map {{ height: 100vh; width: 100%; }}
        .info {{ padding: 6px 8px; background: white; background: rgba(255,255,255,0.8); box-shadow: 0 0 15px rgba(0,0,0,0.2); border-radius: 5px; }}
        .legend {{ line-height: 18px; color: #555; }}
        .legend i {{ width: 18px; height: 18px; float: left; margin-right: 8px; opacity: 0.7; }}
    </style>
</head>
<body>
    <div id="map"></div>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
    <script>
        var map = L.map('map').setView([20, 0], 2);

        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
            maxZoom: 18
        }}).addTo(map);

        var heatData = [
"""

        # Add heat map points
        for (lat, lon), count in coord_counts.items():
            intensity = min(count / 10, 1.0)  # Normalize intensity
            html += f"            [{lat}, {lon}, {intensity}],\n"

        html += """        ];

        L.heatLayer(heatData, {
            radius: 25,
            blur: 35,
            maxZoom: 10,
            max: 1.0,
            gradient: {0.4: 'blue', 0.6: 'lime', 0.8: 'yellow', 1.0: 'red'}
        }).addTo(map);

        // Add info box
        var info = L.control();
        info.onAdd = function (map) {
            this._div = L.DomUtil.create('div', 'info');
            this.update();
            return this._div;
        };

        info.update = function (props) {
            this._div.innerHTML = '<h4>Honeypot Attack Heat Map</h4>' +
                '<b>Total Attacks:</b> """ + str(geo_data['statistics']['total_attacks']) + """<br />' +
                '<b>Countries:</b> """ + str(geo_data['statistics']['unique_countries']) + """<br />' +
                '<b>Cities:</b> """ + str(geo_data['statistics']['unique_cities']) + """';
        };

        info.addTo(map);
    </script>
</body>
</html>"""

        with open(output_file, 'w') as f:
            f.write(html)

        print(f"[+] Heat map generated: {output_file}")

    def export_markdown_report(self, geo_data: Dict, output_file: str):
        """Export geographic analysis as Markdown report"""
        print(f"[*] Generating Markdown report: {output_file}")

        stats = geo_data['statistics']

        with open(output_file, 'w') as f:
            f.write("# Geographic Threat Intelligence Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

            # Executive summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total Attacks:** {stats['total_attacks']:,}\n")
            f.write(f"- **Unique Countries:** {stats['unique_countries']}\n")
            f.write(f"- **Unique Cities:** {stats['unique_cities']}\n")
            f.write(f"- **Attack Corridors:** {stats['attack_corridors_count']}\n")
            f.write(f"- **Geographic Diversity:** {stats['geographic_diversity_score']:.1%}\n\n")

            # Top countries
            f.write("## Top 10 Countries by Attack Volume\n\n")
            f.write("| Rank | Country | Attack Count | % of Total |\n")
            f.write("|------|---------|--------------|------------|\n")

            for idx, (country, count) in enumerate(stats['top_countries'], 1):
                pct = (count / stats['total_attacks']) * 100
                f.write(f"| {idx} | {country} | {count:,} | {pct:.1f}% |\n")

            # Top cities
            f.write("\n## Top 10 Cities by Attack Volume\n\n")
            f.write("| Rank | City | Attack Count |\n")
            f.write("|------|------|---------------|\n")

            for idx, (city, count) in enumerate(stats['top_cities'], 1):
                f.write(f"| {idx} | {city} | {count:,} |\n")

            # Attack corridors
            f.write("\n## Attack Corridors (High-Risk Sources)\n\n")

            for country, data in geo_data['attack_corridors'].items():
                f.write(f"### {country}\n\n")
                f.write(f"- **Threat Level:** {data['threat_level']}\n")
                f.write(f"- **Total Attacks:** {data['total_attacks']:,}\n")
                f.write(f"- **Unique IPs:** {data['unique_ips']}\n")
                f.write(f"- **Top Cities:** {', '.join([city for city, _ in data['top_cities'][:3]])}\n\n")

        print(f"[+] Markdown report generated")


def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description='Geographic analysis of honeypot attacks'
    )

    parser.add_argument('--es-host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--es-port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--days', type=int, default=7, help='Days to analyze')
    parser.add_argument('--geoip-db', default='/usr/share/GeoIP/GeoLite2-City.mmdb',
                        help='GeoIP database path')
    parser.add_argument('--output-json', default='geo_analysis.json',
                        help='JSON output file')
    parser.add_argument('--output-heatmap', default='attack_heatmap.html',
                        help='HTML heat map file')
    parser.add_argument('--output-report', default='geo_report.md',
                        help='Markdown report file')

    args = parser.parse_args()

    print("=" * 60)
    print("GEOLOCATION ANALYSIS ENGINE")
    print("=" * 60)

    # Initialize mapper
    mapper = GeolocationMapper(args.es_host, args.es_port, args.geoip_db)

    # Analyze geographic distribution
    geo_data = mapper.analyze_geographic_distribution(args.days)

    # Export results
    mapper.export_json(geo_data, args.output_json)
    mapper.export_heatmap_html(geo_data, args.output_heatmap)
    mapper.export_markdown_report(geo_data, args.output_report)

    # Print summary
    print("\n" + "=" * 60)
    print("GEOGRAPHIC ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total Attacks: {geo_data['statistics']['total_attacks']:,}")
    print(f"Unique Countries: {geo_data['statistics']['unique_countries']}")
    print(f"Attack Corridors: {geo_data['statistics']['attack_corridors_count']}")
    print("=" * 60)


if __name__ == '__main__':
    main()
