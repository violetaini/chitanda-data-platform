import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('edge', root / 'deploy/tunnel-control/harden-edge.py')
edge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(edge)
fixture = '''server {
    client_max_body_size 3m;
    ssl_certificate /private/certificate.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location ^~ /tunnel/ {
        proxy_pass http://127.0.0.1:5092;
        proxy_set_header X-Real-IP $datahub_client_ip;
        add_header Cache-Control "private, no-store, max-age=0" always;
    }
    location = /transit-node/sync {
        proxy_pass http://127.0.0.1:5092;
    }
    location ~ ^/transit-node/(release|status)$ {
        proxy_pass http://127.0.0.1:5092;
    }
}
'''


class EdgeTests(unittest.TestCase):
    def test_idempotent_scoped_limits_preserve_identity_tls_and_targets(self):
        result = edge.harden(fixture)
        self.assertEqual(result, edge.harden(result))
        self.assertIn('ssl_certificate /private/certificate.pem;', result)
        self.assertEqual(result.count('X-Real-IP $datahub_client_ip;'), 2)
        self.assertEqual(result.count('limit_req zone=datahub_node_rate'), 2)
        self.assertEqual(result.count('limit_req zone=datahub_control_rate'), 1)
        self.assertIn('client_max_body_size 32k;', result)
        self.assertNotIn('private, no-store, max-age=0', result)
        self.assertIn('add_header Strict-Transport-Security "max-age=31536000" always;', result)
        self.assertNotIn('private, no-store, max-age=0', edge.harden(result.replace('        proxy_pass', '        add_header Cache-Control "private, no-store, max-age=0" always;\n        proxy_pass')))
        self.assertIn('if ($datahub_admin_allowed = 0) { return 403; }', result)
        self.assertNotIn('X-Forwarded-For $http_', result)
        with self.assertRaises(ValueError):
            edge.harden(fixture.replace('client_max_body_size 3m;', 'client_max_body_size 8m;'))

    def test_invalid_nginx_configuration_restores_original_files(self):
        with tempfile.TemporaryDirectory(prefix='ct-edge-') as directory:
            vhost = pathlib.Path(directory) / 'site.conf'
            limits = pathlib.Path(directory) / 'http.conf'
            vhost.write_text(fixture)
            original = vhost.read_bytes()
            with patch.object(sys, 'argv', ['harden-edge', '--vhost', str(vhost), '--http-output', str(limits)]), patch.object(edge.subprocess, 'run', side_effect=[subprocess.CalledProcessError(1, 'nginx'), None]):
                with self.assertRaises(subprocess.CalledProcessError):
                    edge.main()
            self.assertEqual(original, vhost.read_bytes())
            self.assertFalse(limits.exists())


if __name__ == '__main__':
    unittest.main()
