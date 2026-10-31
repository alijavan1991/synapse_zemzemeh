# Copyright 2026 Zemzemeh
# SPDX-License-Identifier: AGPL-3.0-only
"""Refuses Matrix media and non-invite rooms, checks file references with Zemzemeh, and tells it who is in a room.

Tied to the pinned Synapse: the subject lookups call the private store, because the module API has none.
Rerun the tests on every Synapse upgrade.
"""
import base64
import json
import logging
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from authlib.jose import JoseError, JsonWebKey, JsonWebToken
from synapse.api.errors import Codes, NotFoundError
from synapse.module_api import (
    NOT_SPAM,
    DirectServeJsonResource,
    ModuleApi,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.util.async_helpers import timeout_deferred

logger = logging.getLogger(__name__)

FILE_REF = "io.zemzemeh.file_ref"
MEDIA_TYPES = {"m.image", "m.file", "m.audio", "m.video", "m.sticker"}
MEDIA_KEYS = {"url", "file", "thumbnail_url", "thumbnail_file"}
TEXT_KEYS = {"body", "formatted_body"}
ROOM_ID = re.compile(r"^![^\s/]{1,254}$")
MXC = re.compile(r"^mxc://", re.I)
REFUSED = (Codes.FORBIDDEN, {})


@dataclass(frozen=True)
class Config:
    issuer: str
    auth_provider: str
    zemzemeh_url: str
    client_id: str
    client_secret: str
    client_scope: str
    membership_client_id: str
    membership_subject: str
    membership_scope: str
    membership_audience: str
    token_max_lifetime_seconds: int
    jwks_refresh_seconds: int
    timeout_seconds: float


def _media_in(value: Any) -> bool:
    """A media key or a bare mxc:// value anywhere. Typed text may mention one without being one."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            for key, child in item.items():
                if key in MEDIA_KEYS:
                    return True
                if key not in TEXT_KEYS:
                    stack.append(child)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, str) and MXC.match(item):
            return True
    return False


def _contents(content: Mapping) -> list[Mapping]:
    """The content, and what an edit would replace it with."""
    new = content.get("m.new_content")
    return [content, new] if isinstance(new, Mapping) else [content]


def _is_webp(data: bytes) -> bool:
    return (len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
            and int.from_bytes(data[4:8], "little") + 8 == len(data))


class _Membership(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, module: "ZemzemehModule"):
        super().__init__(clock=module.clock)
        self._module = module

    async def _async_render_GET(self, request):
        auth = request.requestHeaders.getRawHeaders(b"Authorization") or [b""]
        args = {key: values[0].decode("utf8", "replace") for key, values in request.args.items() if values}
        return await self._module.membership(auth[0].decode("utf8", "replace"), args.get(b"sub"), args.get(b"room"))


class ZemzemehModule:
    def __init__(self, config: Config, api: ModuleApi):
        self.config = config
        self.api = api
        self.clock = api._clock
        self._store = api._store
        self._jwt = JsonWebToken(["RS256"])
        self._metadata: dict | None = None
        self._keys = None
        self._keys_fetched = 0.0
        self._token: str | None = None
        self._token_expires = 0.0
        api.register_web_resource("/_zemzemeh/membership", _Membership(self))
        api.register_spam_checker_callbacks(
            check_event_for_spam=self.check_event_for_spam,
            user_may_create_room=self.user_may_create_room,
            check_media_file_for_spam=self.check_media_file_for_spam,
        )

    @staticmethod
    def parse_config(config: dict) -> Config:
        return Config(
            issuer=config["issuer"].rstrip("/"),
            auth_provider=config["auth_provider"],
            zemzemeh_url=config["zemzemeh_url"].rstrip("/"),
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            client_scope=config["client_scope"],
            membership_client_id=config["membership_client_id"],
            membership_subject=config["membership_subject"],
            membership_scope=config["membership_scope"],
            membership_audience=config["membership_audience"],
            token_max_lifetime_seconds=int(config.get("token_max_lifetime_seconds", 300)),
            jwks_refresh_seconds=int(config.get("jwks_refresh_seconds", 30)),
            timeout_seconds=float(config.get("timeout_seconds", 3)),
        )

    async def _timed(self, call, *args, **kwargs) -> Any:
        waiting = run_in_background(call, *args, **kwargs)
        return await make_deferred_yieldable(
            timeout_deferred(deferred=waiting, timeout=self.config.timeout_seconds, clock=self.clock))

    async def _oidc_metadata(self) -> dict:
        if self._metadata is None:
            self._metadata = await self._timed(
                self.api.http_client.get_json, f"{self.config.issuer}/.well-known/openid-configuration")
        return self._metadata

    # --- Events and rooms ---

    async def check_event_for_spam(self, event) -> Any:
        # Mapping, not dict: Synapse may hand over its immutable mappings.
        content = event.content
        if event.type == "m.room.join_rules":
            return NOT_SPAM if content.get("join_rule") == "invite" else REFUSED
        # Encrypted content cannot be read here. Without the bytes path there is nothing for it to point at.
        if event.type in ("m.room.encrypted", "m.room.avatar"):
            return NOT_SPAM
        if event.type == "m.room.member":
            content = {key: value for key, value in content.items() if key != "avatar_url"}
        if event.type in MEDIA_TYPES or _media_in(content):
            return REFUSED
        references = []
        for part in _contents(content):
            msgtype = part.get("msgtype")
            if msgtype in MEDIA_TYPES:
                return REFUSED
            if msgtype == FILE_REF:
                references.append(part)
        for reference in references:
            if not await self._send_allowed(event, reference):
                return REFUSED
        return NOT_SPAM

    async def _send_allowed(self, event, reference: Mapping) -> bool:
        try:
            subject = await self._subject_of(event.sender)
            if subject is None:
                return False
            reply = await self._timed(
                self.api.http_client.post_json_get_json,
                f"{self.config.zemzemeh_url}/api/chat/internal/validate-send",
                {"sender_sub": subject, "room_id": event.room_id,
                 "file_id": reference.get("file_id"), "file_version": reference.get("file_version")},
                headers={"Authorization": [f"Bearer {await self._service_token()}"]},
            )
        except Exception as exc:
            # The type only: its text can carry URLs. Any failure refuses the event.
            logger.warning("validate-send failed: %s", type(exc).__name__)
            self._token = None
            return False
        return isinstance(reply, dict) and reply.get("allowed") is True

    async def _subject_of(self, mxid: str) -> str | None:
        for provider, subject in await self._store.get_external_ids_by_user(mxid):
            if provider == self.config.auth_provider:
                return subject
        return None

    async def _service_token(self) -> str:
        if self._token and time.time() < self._token_expires:
            return self._token
        metadata = await self._oidc_metadata()
        reply = await self._timed(
            self.api.http_client.post_urlencoded_get_json, metadata["token_endpoint"],
            {"grant_type": "client_credentials", "client_id": self.config.client_id,
             "client_secret": self.config.client_secret, "scope": self.config.client_scope})
        token, lifetime = reply["access_token"], float(reply["expires_in"])
        if not isinstance(token, str) or not token:
            raise ValueError("Malformed token reply")
        # Stop using a token one request timeout before it expires.
        self._token, self._token_expires = token, time.time() + lifetime - self.config.timeout_seconds
        return token

    async def user_may_create_room(self, user_id: str, room_config: dict | None = None) -> Any:
        room_config = room_config or {}
        rules = [item.get("content", {}).get("join_rule") for item in room_config.get("initial_state", [])
                 if item.get("type") == "m.room.join_rules"]
        if (room_config.get("preset") == "public_chat" or room_config.get("visibility") == "public"
                or any(rule != "invite" for rule in rules)):
            return REFUSED
        return NOT_SPAM

    async def check_media_file_for_spam(self, file_wrapper, file_info) -> Any:
        """Behind the gateway every upload is already WebP; anything else got here some other way.
        This also runs on the thumbnails Synapse makes itself, which no client can supply."""
        if file_info.thumbnail is not None:
            return NOT_SPAM
        chunks: list[bytes] = []
        await file_wrapper.write_chunks_to(chunks.append)
        return NOT_SPAM if _is_webp(b"".join(chunks)) else REFUSED

    # --- Membership lookups from Zemzemeh ---

    async def membership(self, authorization: str, sub: str | None, room: str | None) -> tuple[int, dict]:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return 401, {"errcode": Codes.MISSING_TOKEN}
        try:
            if not await self._service_token_valid(token):
                return 401, {"errcode": Codes.UNKNOWN_TOKEN}
        except Exception as exc:
            logger.warning("Service token check failed: %s", type(exc).__name__)
            return 503, {"errcode": Codes.UNKNOWN}
        if not sub or not room or len(sub) > 255 or not ROOM_ID.match(room):
            return 400, {"errcode": Codes.INVALID_PARAM}
        # By subject only: a username equal to someone's subject must find nobody.
        mxid = await self._store.get_user_by_external_id(self.config.auth_provider, sub)
        try:
            state = await self.api.get_room_state(room, [("m.room.join_rules", ""), ("m.room.member", mxid or "")])
        except NotFoundError:
            state = {}
        rule = state.get(("m.room.join_rules", ""))
        member = state.get(("m.room.member", mxid)) if mxid else None
        return 200, {"joined": bool(member and member.content.get("membership") == "join"),
                     "join_rule": rule.content.get("join_rule") if rule else None}

    async def _service_token_valid(self, token: str) -> bool:
        """Failures to reach Keycloak raise, so the caller answers 503 rather than a false no."""
        try:
            header_kid = self._jwt_kid(token)
        except ValueError:
            return False
        keys = await self._signing_keys(header_kid)
        try:
            claims = self._jwt.decode(token, keys)
        except (JoseError, ValueError):
            return False
        now = time.time()
        issued, expires = claims.get("iat"), claims.get("exp")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        return (claims.get("iss", "").rstrip("/") == self.config.issuer
                and claims.get("sub") == self.config.membership_subject
                and claims.get("azp") == self.config.membership_client_id
                and self.config.membership_audience in audiences
                and self.config.membership_scope in str(claims.get("scope", "")).split()
                and isinstance(issued, (int, float)) and isinstance(expires, (int, float))
                and issued <= now < expires
                and expires - issued <= self.config.token_max_lifetime_seconds)

    @staticmethod
    def _jwt_kid(token: str) -> str | None:
        header = token.split(".")[0]
        try:
            return json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))).get("kid")
        except Exception as exc:
            raise ValueError("Malformed token") from exc

    async def _signing_keys(self, kid: str | None):
        known = self._keys is not None and any(key.kid == kid for key in self._keys.keys)
        recently = time.time() - self._keys_fetched < self.config.jwks_refresh_seconds
        if known or (self._keys is not None and recently):
            return self._keys
        metadata = await self._oidc_metadata()
        self._keys = JsonWebKey.import_key_set(await self._timed(self.api.http_client.get_json, metadata["jwks_uri"]))
        self._keys_fetched = time.time()
        return self._keys
