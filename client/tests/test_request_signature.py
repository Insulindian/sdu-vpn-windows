import json
import unittest
from unittest.mock import patch
import requests
from sdu_connect.portal import Portal
from sdu_connect.request_signature import derive_request_key, sign_request


def response(data):
    r = requests.Response()
    r.status_code = 200
    r._content = json.dumps({'code': 0, 'data': data}).encode()
    return r


class RequestSignatureTest(unittest.TestCase):
    def test_native_key_derivation_vector(self):
        self.assertEqual(derive_request_key('TEST-RSA-N', '10001', 'TEST-CHALLENGE').hex().upper(),
                         '6CD0D6662106D5E32FA96F96FCAF694A8678351DEC535D229504935F59E5DCAD')

    def test_native_request_signature_vector(self):
        self.assertEqual(sign_request(b'TEST-KEY', '/test?platform=Mac', b'{"test":1}'),
                         '1A288A7281388E528A8124660983EEE6B0E2AC4D6E0FE88D87A4B968ABABF93F')

    def test_api_signs_exact_encoded_query_and_utf8_entity(self):
        p = Portal()
        p._request_key = b'TEST-KEY'
        with patch.object(p.session, 'request', return_value=response({})) as request:
            p._api('POST', '/controller/v1/public/example', query={'name': 'a b&c'}, json={'test': '中文'})
        kwargs = request.call_args.kwargs
        prepared = p.session.prepare_request(requests.Request('POST', request.call_args.args[1],
            params=kwargs['params'], data=kwargs['data'], headers=kwargs['headers']))
        self.assertEqual(kwargs['headers']['X-Request-Sig'],
                         sign_request(b'TEST-KEY', prepared.path_url, prepared.body))
        self.assertIn('name=a+b%26c', prepared.path_url)
        self.assertEqual(json.loads(prepared.body), {'test': '中文'})

    def test_new_auth_config_rotates_and_clears_stale_key(self):
        p = Portal()
        a = {'devicePubKeyMod': 'TEST-N', 'devicePubKeyExp': '10001', 'challenge': 'FIRST'}
        with patch.object(p.session, 'get', side_effect=[response({'antiMITMAttackData': a}),
             response({'antiMITMAttackData': dict(a, challenge='SECOND')}), response({})]):
            p.auth_config()
            first = p._request_key
            p.auth_config()
            self.assertNotEqual(first, p._request_key)
            p.auth_config()
            self.assertIsNone(p._request_key)


if __name__ == '__main__':
    unittest.main()
