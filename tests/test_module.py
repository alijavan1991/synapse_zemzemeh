# Copyright 2026 Zemzemeh
# SPDX-License-Identifier: AGPL-3.0-only
"""Run in the pinned Synapse image: python -m unittest discover -s tests -t ."""
import time
import unittest
from types import SimpleNamespace

from authlib.jose import JsonWebKey, jwt
from synapse.api.errors import Codes, NotFoundError
from synapse.logging.context import LoggingContext
from synapse.module_api import NOT_SPAM
from synapse.util.clock import Clock
from synapse.util.frozenutils import freeze
from twisted.internet import defer, task

from synapse_zemzemeh import ZemzemehModule

ISSUER = "http://sso.example/realms/z"
ROOM = "!room:example"
FILE_ID = "a" * 32
VERSION = "b" * 64
SERVICE_SUBJECT = "service-account-subject"
REFUSED = (Codes.FORBIDDEN, {})
KEY = JsonWebKey.generate_key("RSA", 2048, {"kid": "k1"}, is_private=True)
OTHER_KEY = JsonWebKey.generate_key("RSA", 2048, {"kid": "k1"}, is_private=True)
TOKEN_SENTINEL = "SENTINEL-SERVICE-CREDENTIAL"


def config(**overrides) -> dict:
    return {"issuer": ISSUER, "auth_provider": "oidc-keycloak", "zemzemeh_url": "http://backend:8000",
            "client_id": "synapse-dlp", "client_secret": TOKEN_SENTINEL, "client_scope": "zemzemeh.chat",
            "membership_client_id": "zemzemeh-chat-service", "membership_subject": SERVICE_SUBJECT,
            "membership_scope": "zemzemeh.membership", "membership_audience": "synapse-dlp", **overrides}


class FakeHttp:
    def __init__(self):
        self.validate = {"allowed": True}
        self.token_replies = 0
        self.jwks_fetches = 0
        self.posts = []
        self.fail_keycloak = False

    async def get_json(self, uri, *args, **kwargs):
        if self.fail_keycloak:
            raise OSError("keycloak down")
        if uri.endswith("/.well-known/openid-configuration"):
            return {"token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs"}
        self.jwks_fetches += 1
        return {"keys": [KEY.as_dict(is_private=False)]}

    async def post_urlencoded_get_json(self, uri, args=None, headers=None):
        if self.fail_keycloak:
            raise OSError("keycloak down")
        self.token_replies += 1
        return {"access_token": f"service-token-{self.token_replies}", "expires_in": 300}

    async def post_json_get_json(self, uri, post_json, headers=None):
        self.posts.append((uri, post_json, headers))
        if isinstance(self.validate, Exception):
            raise self.validate
        if self.validate == "hang":
            await defer.Deferred()
        return self.validate


class FakeStore:
    def __init__(self):
        self.subjects = {"sub-alice": "@alice:example", "sub-bob": "@bob:example"}

    async def get_user_by_external_id(self, provider, sub):
        return self.subjects.get(sub) if provider == "oidc-keycloak" else None

    async def get_external_ids_by_user(self, mxid):
        return [("other", "wrong")] + [("oidc-keycloak", sub) for sub, user in self.subjects.items() if user == mxid]


class FakeApi:
    def __init__(self, clock):
        self._clock = clock
        self._store = FakeStore()
        self.http_client = FakeHttp()
        self.resources = {}
        self.callbacks = {}
        self.state = {
            ("m.room.join_rules", ""): SimpleNamespace(content={"join_rule": "invite"}),
            ("m.room.member", "@alice:example"): SimpleNamespace(content={"membership": "join"}),
            ("m.room.member", "@bob:example"): SimpleNamespace(content={"membership": "invite"}),
            ("m.room.member", "sub-alice"): SimpleNamespace(content={"membership": "join"}),
        }

    def register_web_resource(self, path, resource):
        self.resources[path] = resource

    def register_spam_checker_callbacks(self, **callbacks):
        self.callbacks = callbacks

    async def get_room_state(self, room, event_filter=None):
        if self.state is None:
            raise NotFoundError("no room")
        return self.state


def event(event_type="m.room.message", content=None, sender="@alice:example", room_id=ROOM):
    # As Synapse hands them over: immutable mappings and tuples, which are not dict or list.
    return SimpleNamespace(type=event_type, content=freeze(content or {}), sender=sender, room_id=room_id)


def reference(**extra):
    return {"msgtype": "io.zemzemeh.file_ref", "body": "Zemzemeh file", "file_id": FILE_ID, "file_version": VERSION, **extra}


class ModuleCase(unittest.TestCase):
    def setUp(self):
        self.reactor = task.Clock()
        self.api = FakeApi(Clock(self.reactor, "example"))
        self.module = ZemzemehModule(ZemzemehModule.parse_config(config()), self.api)
        self.http = self.api.http_client

    def run_now(self, coroutine, advance=None):
        with LoggingContext(name="test", server_name="example"):
            waiting = defer.ensureDeferred(coroutine)
            if advance:
                self.reactor.advance(advance)
        self.assertTrue(waiting.called, "did not finish")
        return self.successResultOf(waiting)

    def successResultOf(self, waiting):
        results = []
        waiting.addBoth(results.append)
        result = results[0]
        if hasattr(result, "raiseException"):
            result.raiseException()
        return result

    def check(self, *args, **kwargs):
        return self.run_now(self.module.check_event_for_spam(event(*args, **kwargs)))


class Media(ModuleCase):
    def test_native_media_messages_are_refused(self):
        for msgtype in ["m.image", "m.file", "m.audio", "m.video", "m.sticker"]:
            self.assertEqual(self.check(content={"msgtype": msgtype, "body": "x"}), REFUSED, msgtype)

    def test_media_event_types_are_refused(self):
        for event_type in ["m.sticker", "m.image", "m.file", "m.audio", "m.video"]:
            self.assertEqual(self.check(event_type, {"body": "x"}), REFUSED, event_type)

    def test_media_keys_are_refused_on_any_message(self):
        for key in ["url", "file", "thumbnail_url", "thumbnail_file"]:
            self.assertEqual(self.check(content={"msgtype": "m.text", "body": "x", key: "anything"}), REFUSED, key)

    def test_media_nested_or_in_a_custom_field_is_refused(self):
        for content in [{"msgtype": "m.text", "body": "x", "info": {"thumbnail_url": "mxc://a/b"}},
                        {"msgtype": "m.text", "body": "x", "custom": ["mxc://a/b"]},
                        {"msgtype": "custom.type", "body": "x", "custom": {"deep": {"file": {"v": "v2"}}}},
                        {"msgtype": "m.text", "body": "x", "m.new_content": {"msgtype": "m.image", "body": "y"}}]:
            self.assertEqual(self.check(content=content), REFUSED, content)

    def test_custom_state_cannot_hold_media(self):
        self.assertEqual(self.check("org.example.state", {"picture": "mxc://a/b"}), REFUSED)

    def test_plain_conversation_passes(self):
        for content in [{"msgtype": "m.text", "body": "hello"},
                        {"msgtype": "m.text", "body": "mxc://a/b is an address", "formatted_body": "mxc://a/b"},
                        {"msgtype": "m.notice", "body": "n"},
                        {"msgtype": "m.emote", "body": "e"}]:
            self.assertEqual(self.check(content=content), NOT_SPAM, content)
        self.assertEqual(self.check("m.reaction", {"m.relates_to": {"key": "x"}}), NOT_SPAM)

    def test_encrypted_events_pass_since_they_cannot_be_read(self):
        self.assertEqual(self.check("m.room.encrypted", {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x"}), NOT_SPAM)

    def test_avatars_pass(self):
        self.assertEqual(self.check("m.room.avatar", {"url": "mxc://a/b"}), NOT_SPAM)
        self.assertEqual(self.check("m.room.member", {"membership": "join", "avatar_url": "mxc://a/b"}), NOT_SPAM)

    def test_a_member_event_may_not_hide_media_elsewhere(self):
        self.assertEqual(self.check("m.room.member", {"membership": "join", "file": "x"}), REFUSED)

    def media_verdict(self, data, thumbnail=None):
        wrapper = SimpleNamespace(write_chunks_to=None)

        async def write(callback):
            callback(data[:5])
            callback(data[5:])
        wrapper.write_chunks_to = write
        return self.run_now(self.module.check_media_file_for_spam(wrapper, SimpleNamespace(thumbnail=thumbnail)))

    def test_synapses_own_thumbnails_may_be_stored(self):
        # It makes them from a stored image, as JPEG or PNG; a client cannot upload one.
        thumbnail = SimpleNamespace(width=32, height=32, method="crop", type="image/jpeg", length=1)
        self.assertEqual(self.media_verdict(b"\xff\xd8\xff" + b"x" * 20, thumbnail=thumbnail), NOT_SPAM)

    def test_only_webp_files_may_be_stored(self):
        body = b"WEBPVP8 " + b"\0" * 20
        webp = b"RIFF" + len(body).to_bytes(4, "little") + body
        self.assertEqual(self.media_verdict(webp), NOT_SPAM)
        for data in [b"%PDF-1.7 " + b"x" * 20, b"PK\x03\x04" + b"x" * 20, b"\x89PNG\r\n\x1a\n" + b"x" * 20, b"",
                     webp + b"appended", b"RIFF" + len(body).to_bytes(4, "little") + b"WAVE" + body[4:]]:
            self.assertEqual(self.media_verdict(data), REFUSED, data[:12])


class FileReferences(ModuleCase):
    def test_zemzemeh_says_yes(self):
        self.assertEqual(self.check(content=reference()), NOT_SPAM)
        uri, body, headers = self.http.posts[0]
        self.assertEqual(uri, "http://backend:8000/api/chat/internal/validate-send")
        self.assertEqual(body, {"sender_sub": "sub-alice", "room_id": ROOM, "file_id": FILE_ID, "file_version": VERSION})
        self.assertEqual(headers["Authorization"], ["Bearer service-token-1"])

    def test_zemzemeh_says_no(self):
        self.http.validate = {"allowed": False}
        self.assertEqual(self.check(content=reference()), REFUSED)

    def test_only_an_explicit_yes_allows(self):
        for reply in [{}, {"allowed": "true"}, {"allowed": 1}, [], None, "yes"]:
            self.http.validate = reply
            self.assertEqual(self.check(content=reference()), REFUSED, reply)

    def test_an_error_fails_closed(self):
        self.http.validate = OSError("zemzemeh down")
        self.assertEqual(self.check(content=reference()), REFUSED)

    def test_a_timeout_fails_closed(self):
        self.http.validate = "hang"
        coroutine = self.module.check_event_for_spam(event(content=reference()))
        self.assertEqual(self.run_now(coroutine, advance=self.module.config.timeout_seconds + 1), REFUSED)

    def test_keycloak_down_fails_closed(self):
        self.http.fail_keycloak = True
        self.assertEqual(self.check(content=reference()), REFUSED)
        self.assertEqual(self.http.posts, [])

    def test_a_sender_with_no_subject_is_refused_without_asking(self):
        self.assertEqual(self.check(content=reference(), sender="@stranger:example"), REFUSED)
        self.assertEqual(self.http.posts, [])

    def test_an_edit_into_a_reference_is_checked(self):
        self.http.validate = {"allowed": False}
        content = {"msgtype": "m.text", "body": "x", "m.new_content": reference()}
        self.assertEqual(self.check(content=content), REFUSED)

    def test_the_service_token_is_reused_then_renewed_after_a_failure(self):
        self.check(content=reference())
        self.check(content=reference())
        self.assertEqual(self.http.token_replies, 1)
        self.http.validate = OSError("rejected")
        self.check(content=reference())
        self.http.validate = {"allowed": True}
        self.check(content=reference())
        self.assertEqual(self.http.token_replies, 2)

    def test_failures_log_no_credential(self):
        self.http.validate = OSError(f"Bearer {TOKEN_SENTINEL}")
        with self.assertLogs("synapse_zemzemeh", level="WARNING") as logs:
            self.check(content=reference())
        self.assertNotIn(TOKEN_SENTINEL, "".join(logs.output))
        self.assertNotIn("Bearer", "".join(logs.output))


class JoinRules(ModuleCase):
    def may_create(self, room_config):
        return self.run_now(self.module.user_may_create_room("@alice:example", room_config))

    def test_changing_to_another_rule_is_refused(self):
        for rule in ["public", "knock", "restricted", "knock_restricted", "private", None]:
            self.assertEqual(self.check("m.room.join_rules", {"join_rule": rule}), REFUSED, rule)

    def test_invite_is_allowed(self):
        self.assertEqual(self.check("m.room.join_rules", {"join_rule": "invite"}), NOT_SPAM)

    def test_creating_an_open_room_is_refused(self):
        for room_config in [{"preset": "public_chat"}, {"visibility": "public"},
                            {"preset": "private_chat", "initial_state": [
                                {"type": "m.room.join_rules", "content": {"join_rule": "public"}}]},
                            {"initial_state": [{"type": "m.room.join_rules", "content": {"join_rule": "knock"}}]},
                            {"initial_state": [{"type": "m.room.join_rules", "content": {}}]}]:
            self.assertEqual(self.may_create(room_config), REFUSED, room_config)

    def test_creating_an_invite_room_is_allowed(self):
        for room_config in [{}, {"preset": "private_chat"}, {"preset": "trusted_private_chat"},
                            {"initial_state": [{"type": "m.room.join_rules", "content": {"join_rule": "invite"}},
                                               {"type": "m.room.encryption", "content": {}}]}, None]:
            self.assertEqual(self.may_create(room_config), NOT_SPAM, room_config)


def service_token(key=KEY, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": SERVICE_SUBJECT, "aud": ["synapse-dlp"], "azp": "zemzemeh-chat-service",
              "scope": "profile zemzemeh.membership", "iat": now, "exp": now + 300, **overrides}
    claims = {name: value for name, value in claims.items() if value is not None}
    return jwt.encode({"alg": "RS256", "kid": "k1"}, claims, key).decode()


class Membership(ModuleCase):
    def ask(self, token=None, sub="sub-alice", room=ROOM):
        token = service_token() if token is None else token
        return self.run_now(self.module.membership(f"Bearer {token}", sub, room))

    def test_a_joined_member(self):
        self.assertEqual(self.ask(), (200, {"joined": True, "join_rule": "invite"}))

    def test_an_invited_user_is_not_joined(self):
        self.assertEqual(self.ask(sub="sub-bob"), (200, {"joined": False, "join_rule": "invite"}))

    def test_an_unknown_subject_is_not_joined(self):
        self.assertEqual(self.ask(sub="sub-nobody")[1]["joined"], False)

    def test_a_username_used_as_a_subject_finds_nobody(self):
        # The room holds a member entry under this exact string, as a username collision would.
        self.api.state[("m.room.member", "alice")] = SimpleNamespace(content={"membership": "join"})
        self.assertEqual(self.ask(sub="alice")[1]["joined"], False)
        self.assertEqual(self.ask(sub="@alice:example")[1]["joined"], False)

    def test_an_unknown_room_answers_with_no_rule(self):
        self.api.state = None
        self.assertEqual(self.ask(), (200, {"joined": False, "join_rule": None}))

    def test_another_join_rule_is_reported(self):
        self.api.state[("m.room.join_rules", "")] = SimpleNamespace(content={"join_rule": "knock"})
        self.assertEqual(self.ask()[1]["join_rule"], "knock")

    def test_the_token_must_be_exactly_the_service_account(self):
        for name, token in {
            "other subject": service_token(sub="someone-else"),
            "other issuer": service_token(iss="http://evil/realms/z"),
            "other audience": service_token(aud=["zemzemeh-chat"]),
            "other client": service_token(azp="synapse"),
            "no scope": service_token(scope="profile"),
            "scope lookalike": service_token(scope="zemzemeh.membershipx"),
            "expired": service_token(iat=int(time.time()) - 400, exp=int(time.time()) - 100),
            "from the future": service_token(iat=int(time.time()) + 100),
            "too long": service_token(exp=int(time.time()) + 3000),
            "no issue time": service_token(iat=None),
            "another key": service_token(key=OTHER_KEY),
            "garbage": "not.a.token",
        }.items():
            self.assertEqual(self.ask(token=token)[0], 401, name)

    def test_unsigned_tokens_are_refused(self):
        header = "eyJhbGciOiJub25lIiwia2lkIjoiazEifQ"
        payload = jwt.encode({"alg": "RS256"}, {"sub": SERVICE_SUBJECT}, KEY).decode().split(".")[1]
        self.assertEqual(self.ask(token=f"{header}.{payload}.")[0], 401)

    def test_a_missing_token(self):
        self.assertEqual(self.run_now(self.module.membership("", "sub-alice", ROOM))[0], 401)
        self.assertEqual(self.run_now(self.module.membership("Basic abc", "sub-alice", ROOM))[0], 401)

    def test_bad_parameters(self):
        for sub, room in [(None, ROOM), ("sub-alice", None), ("sub-alice", "room"), ("x" * 256, ROOM)]:
            self.assertEqual(self.ask(sub=sub, room=room)[0], 400, (sub, room))

    def test_keycloak_unreachable_is_an_outage_not_a_denial(self):
        self.http.fail_keycloak = True
        self.assertEqual(self.ask()[0], 503)

    def test_keys_are_fetched_once(self):
        self.ask()
        self.ask()
        self.assertEqual(self.http.jwks_fetches, 1)

    def test_an_unknown_key_does_not_fetch_on_every_request(self):
        self.ask()
        foreign = jwt.encode({"alg": "RS256", "kid": "other"}, {"sub": SERVICE_SUBJECT}, OTHER_KEY).decode()
        self.ask(token=foreign)
        self.ask(token=foreign)
        self.assertEqual(self.http.jwks_fetches, 1)

    def test_the_resource_is_registered(self):
        self.assertIn("/_zemzemeh/membership", self.api.resources)


class Pinned(unittest.TestCase):
    def test_private_lookups_still_exist(self):
        from synapse.storage.databases.main.registration import RegistrationWorkerStore
        self.assertIn("get_user_by_external_id", vars(RegistrationWorkerStore))
        self.assertIn("get_external_ids_by_user", vars(RegistrationWorkerStore))


if __name__ == "__main__":
    unittest.main()
