# Troubleshooting

## Plugin does not enable

Check:

- Server runs Java 21
- PacketEvents is installed
- Console for dependency or startup fail-fast messages

## Players can still act before login/register

Check:

- `block-movement-while-unauthed: true`
- `block-chat-while-unauthed: true`
- command whitelist in `auth.allowed-commands-while-unauthed`
- no conflicting plugin overriding events

## Premium users are denied

Check:

- `premium-verification-mode`
- proxy trust settings (`trusted-proxy-premium-identity`)
- Mojang/API reachability

If your environment is not fully trusted, use `compatibility`.

## Rate limits trigger too aggressively

Tune:

- `rate-limit.window-seconds`
- action-specific attempts/cooldowns (`pre-login`, `login`, `register`)

## IP checks block legitimate users

Tune:

- `security.ip-intelligence.fail-open`
- `deny-proxy`, `deny-hosting`, `deny-mobile`, `deny-unknown`
- request timeout and cache values

## Database issues

Check:

- write permissions in plugin folder
- SQLite file path (`database-file`)
- server logs for SQL exceptions

