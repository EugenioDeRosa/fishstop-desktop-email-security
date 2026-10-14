import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import requests

from fishstop_engine import reputation, vt_transport


class NetworkPreferencesTests(unittest.TestCase):
    def test_local_only_enrichment_has_no_network_jobs(self):
        report = {"links": [{"url": "https://example.invalid", "scheme": "https"}],
                  "from_": "sender@example.invalid", "received_hops": [{"sender_ip": "8.8.8.8"}],
                  "attachments": [{"hash_sha256": "a" * 64}]}
        with patch.object(reputation, "vt_get", side_effect=AssertionError("network")), \
             patch.object(reputation, "check_hop_ip", side_effect=AssertionError("network")), \
             patch.object(reputation, "check_rdap_domain", side_effect=AssertionError("network")), \
             patch.object(reputation, "geolocate", side_effect=AssertionError("network")):
            reputation.enrich(report, "key", "key", disabled_providers={"local_only"})
        self.assertEqual(report["domain_reputation"]["example.invalid"]["rdap"]["status"], "disabled")

    def test_default_opt_in_services_are_not_called(self):
        with patch.object(reputation, "check_spamhaus") as spamhaus, \
             patch.object(reputation, "geolocate") as geo:
            reputation.enrich({"received_hops": [{"sender_ip": "8.8.8.8"}]}, "", "")
            spamhaus.assert_not_called()
            geo.assert_not_called()

    def test_spamhaus_independent_of_abuseipdb(self):
        with patch.object(reputation, "check_ip", return_value={"status": "ok"}), \
             patch.object(reputation, "check_spamhaus", return_value={"status": "clean"}) as spamhaus:
            reputation.check_hop_ip("abuse-key", "8.8.8.8", spamhaus_enabled=True)
            spamhaus.assert_called_once_with("8.8.8.8")

    def test_guard_blocks_external_tcp_udp_dns_but_allows_loopback(self):
        code = '''
import socket
from fishstop_engine.network_policy import install_local_only_guard
install_local_only_guard()
for action in [lambda: socket.getaddrinfo('example.com',443),
               lambda: socket.gethostbyname('example.com'),
               lambda: socket.gethostbyaddr('8.8.8.8'),
               lambda: socket.socket().connect(('8.8.8.8',443)),
               lambda: socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('8.8.8.8',53))]:
    try: action()
    except OSError: pass
    else: raise AssertionError('External access permitted')
server=socket.socket();server.bind(('127.0.0.1',0));server.listen()
client=socket.socket();client.connect(server.getsockname());client.close();server.close()
socket.getaddrinfo('localhost',80)
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_vt_cache_and_quota_are_persistent(self):
        result = requests.Response();result.status_code = 200;result._content = b'{"data":{}}'
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"FISHSTOP_VT_CACHE_PATH": str(Path(directory) / "cache.sqlite")}), \
             patch.object(vt_transport.requests, "get", return_value=result) as get:
            for index in range(4):
                self.assertEqual(vt_transport.get(f"https://vt/{index}", headers={"x-apikey": "key"}, timeout=1).status_code, 200)
            self.assertEqual(vt_transport.get("https://vt/0", headers={"x-apikey": "key"}, timeout=1).status_code, 200)
            self.assertEqual(vt_transport.get("https://vt/new", headers={"x-apikey": "key"}, timeout=1).status_code, 429)
            self.assertEqual(get.call_count, 4)
