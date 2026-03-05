# Installation

## Requirements

- Java 21
- Paper or Purpur 1.21+
- PacketEvents plugin

## Steps

1. Download and install `PacketEvents` in your server `plugins/` folder.
2. Download `AuthManager-BETA-1.4.jar`.
3. Place the jar in `plugins/`.
4. Start server once to generate default config files.
5. Configure `plugins/AuthManager/config.yml`.
6. Restart server.

## Verify Startup

After startup, check console logs:

- AuthManager should be enabled.
- PacketEvents dependency should be detected.
- No startup fail-fast error should appear.

## Update Notes

When updating from older builds:

1. Stop the server.
2. Replace old AuthManager jar with the new one.
3. Keep your existing config and message files.
4. Start server and verify logs.

