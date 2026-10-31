# synapse_zemzemeh

Synapse module for Zemzemeh's Matrix chat. AGPL-3.0-only, because it runs inside Synapse.

- Refuses native media events and any `url`, `file` or `mxc://` value outside avatars.
- Asks Zemzemeh's `validate-send` about each file reference it can read, and refuses on anything but an explicit yes,
  including timeouts and errors. It cannot read encrypted events.
- Refuses every join rule except `invite`, at room creation and later.
- Refuses to store any media that is not one complete WebP file. The avatar gateway is the first layer.
- Serves `/_zemzemeh/membership` to one exact service account, mapping users by OIDC subject, never by username.
  Nginx hides it from the public.

Tied to the pinned Synapse (1.164.1): subject lookups call the private `_store`, since the module API has none.
Rerun the tests on each upgrade.

```yaml
modules:
  - module: synapse_zemzemeh.ZemzemehModule
    config:
      issuer: https://sso.example.com/realms/zemzemeh
      auth_provider: oidc-keycloak
      zemzemeh_url: http://backend:8000
      client_id: synapse-dlp
      client_secret: "..."
      client_scope: zemzemeh.chat
      membership_client_id: zemzemeh-chat-service
      membership_subject: "<the service account's sub>"
      membership_scope: zemzemeh.membership
      membership_audience: synapse-dlp
      # Optional: token_max_lifetime_seconds 300, jwks_refresh_seconds 30, timeout_seconds 3
```

Set `max_upload_size` to the gateway's output limit.

Tests, in the pinned image, from this directory:

```bash
docker run --rm --entrypoint python -v "$PWD:/m:ro" -e PYTHONPATH=/m -w /m ghcr.io/element-hq/synapse:v1.164.1 -m unittest tests.test_module
```
