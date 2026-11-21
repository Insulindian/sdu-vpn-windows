"""Offline protocol tests: no credentials, browser or VPN traffic."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import requests

from sdu_connect.cli import _adopt_session, build_parser, _apply
from sdu_connect.config import Config
from sdu_connect.portal import Portal, PortalError, CLIENT_UA


def response(body=None, *, status=200, location=None):
    result = requests.Response()
    result.status_code = status
    result.headers['x-sdp-random'] = 'TEST-NONCE'
    result._content = json.dumps(body).encode()
    if location:
        result.headers['Location'] = location
    return result


def callback():
    return response(status=302, location='https://vpn.sdu.edu.cn/portal/shortcut.html?' +
                    urlencode({'data': json.dumps({'ticket': 'ENV-ONLY'})}))


def auth_config():
    return response({'code': 0, 'data': {'isLogin': 1, 'security': {'csrfToken': 'REFRESHED'}}})


RESOURCE = {'code': 0, 'data': {'appList': {'data': {'config': {
    'nodeGroupConf': {'majorNodeGroup': {'id': 'g1'}}}}}}}


class ClientProtocolTest(unittest.TestCase):
    def setUp(self):
        collector = patch('sdu_connect.portal.collect_endpoint', side_effect=lambda device, requested: {
            'device_id': device, 'device': {'type': 'MacBookAirTEST'},
            'os': {'family': 'macOS', 'version': '26.0', 'arch': 'arm64'},
        })
        collector.start()
        self.addCleanup(collector.stop)

    def test_order_ticket_types_and_device_id(self):
        portal = Portal()
        with patch.object(portal.session, 'get', side_effect=[callback(), auth_config(), auth_config()]), \
             patch.object(portal.session, 'request', side_effect=[
                 response({'code': 0, 'data': {'env': [], 'ticket': 'ENV-ROTATED'}}),
                 response({'code': 0}),
                 response({'code': 0, 'data': {'sidTicket': 'SID-ONLY'}}),
                 response({'code': 0}), response(RESOURCE),
             ]) as call:
            self.assertEqual(portal.complete_cas('pass.sdu.edu.cn', 'ST-ONLY', 'device1'), RESOURCE)
        calls = call.call_args_list
        self.assertTrue(calls[0].args[1].endswith('/endpointStrategy'))
        self.assertEqual(calls[0].kwargs['params']['ticket'], 'ENV-ONLY')
        self.assertTrue(calls[1].args[1].endswith('/reportEnv'))
        self.assertEqual(json.loads(calls[1].kwargs['data'])['ticket'], 'ENV-ROTATED')
        self.assertEqual(json.loads(calls[1].kwargs['data'])['deviceId'], 'device1')
        from sdu_connect.report_signature import sign_report
        self.assertEqual(calls[1].kwargs['headers']['x-sdp-signature'], sign_report('TEST-NONCE', calls[1].kwargs['data']))
        self.assertEqual(json.loads(calls[1].kwargs['data'])['env']['endpoint']['device_id'], 'device1')
        self.assertTrue(calls[2].args[1].endswith('/authCheck'))
        self.assertEqual(calls[3].kwargs['json'], {'sidTicket': 'SID-ONLY'})
        self.assertIn('SPCClientType', portal.session.headers['User-Agent'])
        self.assertEqual(portal.session.headers['x-csrf-token'], 'REFRESHED')

    def test_business_error_is_not_success_even_on_http_200(self):
        portal = Portal()
        with patch.object(portal.session, 'request', return_value=response(
            {'code': 75500304, 'message': 'expired'})):
            with self.assertRaisesRegex(PortalError, '75500304'):
                portal._api('POST', '/test')

    def test_denied_terminal_policy_stops_before_resource(self):
        portal = Portal()
        with patch.object(portal.session, 'get', side_effect=[callback(), auth_config()]), \
             patch.object(portal.session, 'request', side_effect=[
                 response({'code': 0, 'data': {'env': [], 'ticket': 'ENV-ROTATED'}}),
                 response({'code': 0}), response({'code': 75500503, 'message': 'denied'})
             ]) as call:
            with self.assertRaisesRegex(PortalError, '75500503'):
                portal.complete_cas('pass.sdu.edu.cn', 'ST-ONLY', 'device1')
            self.assertEqual(call.call_count, 3)

    def test_unfinished_second_factor_does_not_export(self):
        portal = Portal()
        with patch.object(portal.session, 'get', side_effect=[callback(), auth_config()]), \
             patch.object(portal.session, 'request', side_effect=[
                 response({'code': 0, 'data': {'env': [], 'ticket': 'ENV-ROTATED'}}),
                 response({'code': 0}), response({'code': 0, 'data': {'nextService': 'auth/sms'}})
             ]):
            with self.assertRaisesRegex(PortalError, 'auth/sms'):
                portal.complete_cas('pass.sdu.edu.cn', 'ST-ONLY', 'device1')

    def test_foreign_callback_is_not_followed(self):
        portal = Portal()
        with patch.object(portal.session, 'get', return_value=response(
            status=302, location='https://other.example/portal/shortcut.html')) as call:
            with self.assertRaises(PortalError):
                portal.complete_cas('pass.sdu.edu.cn', 'ST-ONLY', 'device1')
            self.assertEqual(call.call_count, 1)

    def test_actual_login_state_required(self):
        portal = Portal()
        with patch.object(portal.session, 'get', side_effect=[callback(), auth_config(),
            response({'code': 0, 'data': {'isLogin': 0}})]), \
             patch.object(portal.session, 'request', side_effect=[
                 response({'code': 0, 'data': {'env': [], 'ticket': 'ENV-ROTATED'}}),
                 response({'code': 0}), response({'code': 0, 'data': {}})
             ]) as call:
            with self.assertRaisesRegex(PortalError, 'isLogin'):
                portal.complete_cas('pass.sdu.edu.cn', 'ST-ONLY', 'device1')
            self.assertEqual(call.call_count, 3)

    def test_export_keeps_reported_device_and_private_permissions(self):
        portal = Portal()
        portal.session.cookies.set('sid', 'TEST-SID', domain='vpn.sdu.edu.cn', path='/')
        portal.session.cookies.set('sid', 'FOREIGN-SID', domain='not-vpn.sdu.edu.cn', path='/')
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'SDU_CONNECT_HOME': tmp}), \
             patch.object(portal, 'complete_cas', return_value=RESOURCE) as complete, \
             contextlib.redirect_stdout(io.StringIO()):
            sid, device_id, resource = _adopt_session(portal, 'pass.sdu.edu.cn', 'ST-ONLY')
            self.assertEqual(sid, 'TEST-SID')
            self.assertEqual(complete.call_args.args[2], device_id)
            state = Path(tmp) / 'client_data.json'
            self.assertEqual(json.loads(state.read_text())['device_id'], device_id)
            if os.name != 'nt':  # Windows has no POSIX mode bits
                self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                self.assertEqual(Path(resource).stat().st_mode & 0o777, 0o600)
            _adopt_session(portal, 'pass.sdu.edu.cn', 'NEW-ST')
            self.assertEqual(complete.call_args.args[2], device_id)

    def test_uppercase_registered_identity_is_preserved(self):
        portal = Portal()
        portal.session.cookies.set('sid', 'TEST-SID', domain='vpn.sdu.edu.cn', path='/')
        registered = 'ABCDEF0123456789ABCDEF0123456789'
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'SDU_CONNECT_HOME': tmp}), \
             patch('sdu_connect.config.official_device_id', return_value=''), \
             patch.object(portal, 'complete_cas', return_value=RESOURCE) as complete, \
             contextlib.redirect_stdout(io.StringIO()):
            (Path(tmp) / 'endpoint_identity.json').write_text(json.dumps({'device_id': registered}))
            _, device_id, _ = _adopt_session(portal, 'pass.sdu.edu.cn', 'ST-ONLY')
            self.assertEqual(device_id, registered)
            self.assertEqual(complete.call_args.args[2], registered)

    def test_failed_auth_does_not_write_credentials(self):
        portal = Portal()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'SDU_CONNECT_HOME': tmp}), \
             patch.object(portal, 'complete_cas', side_effect=PortalError('denied')):
            with self.assertRaises(SystemExit):
                _adopt_session(portal, 'pass.sdu.edu.cn', 'ST-ONLY')
            self.assertFalse((Path(tmp) / 'client_data.json').exists())
            self.assertFalse((Path(tmp) / 'resource.json').exists())
            self.assertTrue((Path(tmp) / 'endpoint_identity.json').exists())

    def test_config_auth_type_and_detach_short_option(self):
        args = build_parser().parse_args(['up', '-d'])
        self.assertTrue(args.detach)
        self.assertEqual(_apply(args, Config(auth_type='auth/psw')).auth_type, 'auth/psw')


if __name__ == '__main__':
    unittest.main()
