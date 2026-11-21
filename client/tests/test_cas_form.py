"""The CAS page embeds several templates; only the login form may be parsed."""

import unittest

from sdu_connect.cas import _parse_login_form, ticket_from_url

PAGE = """
<html><body>
<div id="template_container">
  <form id="phoneForm" action="/cas/mobile">
    <input type="text" id="loginMobile" name="mobile" value="">
    <input type="text" id="sendConfirm" name="code" value="">
  </form>
</div>
<form id="loginForm" action="/cas/login?service=https%3A%2F%2Fvpn.sdu.edu.cn%3A443%2Fpassport%2Fv1%2Fauth%2Fcas" method="post">
  <input type="hidden" id="rsa" name="rsa"/>
  <input type="hidden" id="ul" name="ul"/>
  <input type="hidden" id="pl" name="pl"/>
  <input type="hidden" id="lt" name="lt" value="LT-1-abc-cas" />
  <input type="hidden" name="execution" value="e1s1" />
  <input type="hidden" name="_eventId" value="submit" />
  <input class="login_box_input" id="un" value="" />
  <input class="login_box_input" id="pd" type="password" value="" />
</form>
</body></html>
"""


class FormParseTest(unittest.TestCase):
    def test_only_login_form(self) -> None:
        action, fields = _parse_login_form(PAGE)
        self.assertEqual(
            action,
            "/cas/login?service=https%3A%2F%2Fvpn.sdu.edu.cn%3A443%2Fpassport%2Fv1%2Fauth%2Fcas",
        )
        self.assertEqual(
            fields,
            {"rsa": "", "ul": "", "pl": "", "lt": "LT-1-abc-cas", "execution": "e1s1", "_eventId": "submit"},
        )
        self.assertNotIn("code", fields)
        self.assertNotIn("mobile", fields)


class TicketTest(unittest.TestCase):
    def test_extract(self) -> None:
        url = "https://vpn.sdu.edu.cn:443/passport/v1/auth/cas?ticket=ST-123-xyz-cas"
        self.assertEqual(ticket_from_url(url), "ST-123-xyz-cas")

    def test_missing(self) -> None:
        self.assertIsNone(ticket_from_url("https://vpn.sdu.edu.cn/passport/v1/auth/cas"))


if __name__ == "__main__":
    unittest.main()
