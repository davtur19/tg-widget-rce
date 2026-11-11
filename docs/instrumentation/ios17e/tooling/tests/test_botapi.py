import unittest

from i17e_runner.botapi import BotClient
from i17e_runner.errors import BotApiError, ConfigError


class BotApiTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def transport(url, body, timeout):
            self.calls.append((url, body, timeout))
            if body.get("message_id") == 404:
                return {"ok": False, "description": "Bad Request: message to delete not found"}
            if body.get("message_id") == 403:
                return {"ok": False, "description": "Bad Request: message can't be deleted for everyone"}
            return {"ok": True, "result": {"message_id": body.get("message_id") or 7001}}

        self.bot = BotClient("FAKE_TOKEN_FOR_TESTS", transport=transport)

    def test_token_is_not_in_safe_endpoint(self):
        safe = self.bot.safe_endpoint("sendWidget")
        self.assertNotIn("FAKE_TOKEN_FOR_TESTS", safe)
        self.assertIn("<BOT_TOKEN>", safe)
        self.assertNotIn("FAKE_TOKEN_FOR_TESTS", repr(self.bot))

    def test_send_widget_body_and_endpoint(self):
        outcome = self.bot.send_widget(12345, "<html/>", allow_queries=True,
                                       background_query=True, height=0, width=0)
        self.assertEqual(outcome.message_id, 7001)
        url, body, timeout = self.calls[0]
        self.assertIn("/beta/botFAKE_TOKEN_FOR_TESTS/sendWidget", url)
        self.assertEqual(body["chat_id"], 12345)
        self.assertEqual(body["html"], "<html/>")
        self.assertTrue(body["allow_queries"])
        self.assertTrue(body["background_query"])
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["width"], 0)
        self.assertEqual(timeout, 30.0)

    def test_send_widget_standard_base(self):
        urls = []

        def transport(url, body, timeout):
            urls.append(url)
            return {"ok": True, "result": {"message_id": 1}}

        bot = BotClient("TOKEN", api="standard", transport=transport)
        bot.send_widget(1, "x")
        self.assertEqual(urls[0], "https://api.telegram.org/botTOKEN/sendWidget")

    def test_delete_deleted_absent_and_hard_failure(self):
        outcome = self.bot.delete_message(12345, 10)
        self.assertEqual(outcome.status, "deleted")
        outcome = self.bot.delete_message(12345, 404)
        self.assertEqual(outcome.status, "absent")
        with self.assertRaises(BotApiError) as ctx:
            self.bot.delete_message(12345, 403)
        self.assertIn("cannot be deleted", str(ctx.exception))

    def test_send_error_raises(self):
        bot = BotClient("TOKEN", transport=lambda url, body, timeout: {
            "ok": False, "description": "Bad Request: chat not found"})
        with self.assertRaises(BotApiError):
            bot.send_widget(1, "x")

    def test_missing_token(self):
        with self.assertRaises(ConfigError):
            BotClient(None)

    def test_chat_value(self):
        self.calls.clear()
        self.bot.delete_message("@channel", 1)
        self.assertEqual(self.calls[0][1]["chat_id"], "@channel")


if __name__ == "__main__":
    unittest.main()
