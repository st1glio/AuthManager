# Configuration

Main file: `plugins/AuthManager/config.yml`

## Core Settings

- `database-file`: SQLite file name
- `min-password-length`: minimum password length
- `auto-login-premium`: auto-login for verified premium users
- `auth-reminder-seconds`: interval for auth reminder messages
- `auth-timeout-seconds`: kick timeout if user does not authenticate
- `block-chat-while-unauthed`: block chat before auth
- `block-movement-while-unauthed`: block movement before auth

## Premium Verification

- `enforce-premium-name-protection`: premium name anti-spoof protection
- `premium-verification-mode`: `strict` or `compatibility`
- `trusted-proxy-premium-identity`: trust premium identity from secured proxy

Guideline:

- Use `strict` only with a trusted setup.
- Use `compatibility` for less strict environments.

## Auth Section

- `auth.blocked-message-cooldown-ms`: anti-spam cooldown for block messages
- `auth.allowed-commands-while-unauthed`: command whitelist before auth

## Session Section

- `session.remember.enabled`: enable remembered sessions
- `session.remember.duration-minutes`: remembered session duration
- `session.remember.require-same-ip`: require same IP for remembered sessions

## Security Section

- `security.startup-fail-fast`: disable plugin on unsafe startup configuration

### IP Intelligence

- `enabled`: enable external lookup checks
- `check-on-pre-login`: run checks during pre-login
- `skip-private-ip`: ignore private/local addresses
- `fail-open`: allow login if lookup service fails
- `deny-proxy`: block proxy IPs
- `deny-hosting`: block hosting/datacenter IPs
- `deny-mobile`: block mobile network IPs
- `deny-unknown`: block unknown-country IPs
- `request-timeout-millis`: request timeout
- `cache-minutes`: lookup cache lifetime
- `ipinfo-token`: optional API token

### Account Lock

- `enabled`: enable account lock policy
- `window-seconds`: counting window for failures
- `max-failures`: max failures before lock
- `lock-seconds`: lock duration

### Multi-account

- `enabled`: enable IP account limit
- `max-accounts-per-ip`: max registered accounts per IP

### Password Policy

- `max-length`: max password length
- `require-uppercase`: require uppercase
- `require-lowercase`: require lowercase
- `require-digit`: require digit
- `require-special`: require special character
- `disallow-username`: reject passwords containing username
- `blocked-list`: blocked weak passwords

## Rate Limit Section

- `rate-limit.enabled`: global switch
- `rate-limit.window-seconds`: shared tracking window

Per action:

- `pre-login.*`
- `login.*`
- `register.*`

Each action supports:

- `max-attempts`
- `base-cooldown-seconds`
- `max-cooldown-seconds`

