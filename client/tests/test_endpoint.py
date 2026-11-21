import unittest
from unittest.mock import patch
from sdu_connect.endpoint import collect_endpoint, EndpointError


class EndpointTest(unittest.TestCase):
    def test_native_model_and_os_are_measured_not_browser_placeholder(self):
        with patch('sdu_connect.endpoint.platform.system', return_value='Darwin'), \
             patch('sdu_connect.endpoint.platform.machine', return_value='arm64'), \
             patch('sdu_connect.endpoint._read', side_effect=['MacBookAir10,1', '26.0']):
            value = collect_endpoint('independent-id')
        self.assertEqual(value['device']['type'], 'MacBookAir10,1')
        self.assertEqual(value['device_id'], 'independent-id')
        self.assertEqual(value['os'], {'family': 'macOS', 'version': '26.0', 'arch': 'arm64'})
        self.assertNotIn('atrust_client', value)
        self.assertNotIn('security', value)

    def test_unknown_security_check_is_not_faked(self):
        with patch('sdu_connect.endpoint.platform.system', return_value='Darwin'), \
             patch('sdu_connect.endpoint._read', side_effect=['MacBookAir10,1', '26.0']):
            with self.assertRaises(EndpointError):
                collect_endpoint('device1', [{'name': 'endpoint.security.is_antivirus_enabled', 'type': 'var'}])

    def test_hostname_only_added_when_requested(self):
        with patch('sdu_connect.endpoint.platform.system', return_value='Darwin'), \
             patch('sdu_connect.endpoint._read', side_effect=['MacBookAir10,1', '26.0']), \
             patch('sdu_connect.endpoint.socket.gethostname', return_value='TEST-HOST'):
            value = collect_endpoint('device1', [{'name': 'endpoint.os.hostname', 'type': 'var'}])
        self.assertEqual(value['os']['hostname'], 'TEST-HOST')

    def test_unsupported_platform_fails_explicitly(self):
        with patch('sdu_connect.endpoint.platform.system', return_value='Linux'):
            with self.assertRaises(EndpointError):
                collect_endpoint('device1')
