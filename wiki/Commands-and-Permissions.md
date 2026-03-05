# Commands and Permissions

## Player Commands

- `/login <password>`
- `/register <password> <confirmation>`
- `/premium`
- `/unpremium`
- `/changepassword <old> <new> <confirmation>`
- `/logout`
- `/authstatus`

Aliases:

- `/l` -> login
- `/reg` -> register
- `/cpass` -> changepassword
- `/lo` -> logout
- `/astatus` -> authstatus

## Admin Commands

- `/lookup <player|ip>`
- `/authadmin <subcommand>`

Authadmin subcommands:

- `help`
- `status`
- `stats`
- `reload`
- `ratelimit`
- `sessions`
- `unlock`
- `setpassword`
- `forceauth`
- `forceunauth`
- `kickunauth`
- `packet`
- `player`

Aliases:

- `/authctl`
- `/astadmin`

## Permissions

- `authmanager.admin`

Required for:

- `/authadmin`
- `/lookup`

Current behavior:

- `/premium` and `/unpremium` do not require a dedicated premium permission.

