import unittest
from unittest.mock import patch
from sdu_connect.report_signature import sign_report
from sdu_connect.portal import Portal, PortalError


class ReportSignatureTest(unittest.TestCase):
    def test_native_synthetic_vector(self):
        # Verified using only synthetic inputs with the installed native function.
        self.assertEqual(sign_report('TEST-NONCE', b'{"test":1}'),
            '3A76F3C353CBEDEF67944237F098D41DC0F149CB7D796AAE6B412983BCC3904E')

    def test_body_whitespace_and_nonce_change_signature(self):
        a = sign_report('TEST-NONCE', b'{"test":1}')
        self.assertNotEqual(a, sign_report('TEST-NONCE', b'{"test": 1}'))
        self.assertNotEqual(a, sign_report('NEW-NONCE', b'{"test":1}'))

    def test_missing_nonce_stops_report_before_network(self):
        portal = Portal()
        with patch.object(portal.session, 'request') as request:
            with self.assertRaisesRegex(PortalError, 'x-sdp-random'):
                portal._api('POST', '/controller/v1/public/reportEnv', json={'env': {}})
            request.assert_not_called()
