# AuthManager

Security-focused authentication plugin for Paper/Purpur servers.

AuthManager provides secure `/register` and `/login` flows, premium identity verification, pre-auth action blocking, and anti-bruteforce protections.

## Version

- Current release: `BETA-1.3`
- Java: `21`
- Minecraft: `1.21+` (Paper/Purpur recommended)

## Requirements

- PacketEvents plugin (required dependency)
- Paper or Purpur server

## Quick Install

1. Install `PacketEvents` in `plugins/`.
2. Copy `AuthManager-BETA-1.3.jar` into `plugins/`.
3. Start the server once to generate files.
4. Edit `plugins/AuthManager/config.yml`.
5. Restart server (or use `/authadmin reload`).

## Main Features

- Register/login authentication system
- Restricts unauthenticated players before login/register
- Premium verification with `strict` and `compatibility` modes
- Rate limiting for pre-login, login, and register
- Account lock after repeated failed attempts
- Optional remembered sessions
- IP intelligence checks (proxy/hosting/mobile/unknown)
- Admin diagnostics and security commands

## Commands

- `/login <password>`
- `/register <password> <confirmation>`
- `/premium`
- `/unpremium`
- `/changepassword <old> <new> <confirmation>`
- `/logout`
- `/authstatus`
- `/lookup <player|ip>`
- `/authadmin <subcommand>`

## Permissions

- `authmanager.admin` -> required for `/authadmin` and `/lookup`

Note: `/premium` and `/unpremium` are public in the current version.

## Wiki

- [Home](wiki/Home.md)
- [Installation](wiki/Installation.md)
- [Configuration](wiki/Configuration.md)
- [Commands and Permissions](wiki/Commands-and-Permissions.md)
- [Troubleshooting](wiki/Troubleshooting.md)
- [Changelog](wiki/Changelog.md)

## License

This project is licensed under the [GPL-3.0](LICENSE).

