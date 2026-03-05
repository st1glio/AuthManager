package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class AuthStatusCommand implements CommandExecutor {
    private static final String YELLOW = "\u00A7e";
    private static final String GRAY = "\u00A77";
    private static final String WHITE = "\u00A7f";

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final AuthService authService;
    private final ConfigManager configManager;

    public AuthStatusCommand(AuthService authService, ConfigManager configManager) {
        this.authService = authService;
        this.configManager = configManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(configManager.getMessage("player-only"));
            return true;
        }

        if (args.length != 0) {
            player.sendMessage(configManager.getMessage("usage-authstatus"));
            return true;
        }

        authService.describeOwnStatusAsync(player, snapshot -> {
            sendLine(player, YELLOW + "Stato autenticazione:");
            sendLine(player, GRAY + "registrato=" + WHITE + snapshot.registered()
                    + GRAY + " premium=" + WHITE + snapshot.premium());
            sendLine(player, GRAY + "autenticato=" + WHITE + snapshot.authenticated()
                    + GRAY + " step=" + WHITE + (snapshot.pendingAuthType() == null ? "-" : snapshot.pendingAuthType().name()));
            sendLine(player, GRAY + "timeout-auth=" + WHITE + snapshot.authSecondsLeft() + "s"
                    + GRAY + " remembered-session=" + WHITE + snapshot.rememberedSessionActive());
            sendLine(player, GRAY + "session-remembered-left=" + WHITE + snapshot.rememberedSessionSecondsLeft() + "s");
            sendLine(player, GRAY + "account-locked=" + WHITE + snapshot.accountLocked()
                    + GRAY + " lock-left=" + WHITE + snapshot.accountLockSecondsLeft() + "s");
            sendLine(player, GRAY + "last-login=" + WHITE + formatEpochMillis(snapshot.lastLoginAt())
                    + GRAY + " ip=" + WHITE + (snapshot.lastLoginIp().isBlank() ? "-" : snapshot.lastLoginIp()));
        });
        return true;
    }

    private void sendLine(Player player, String line) {
        player.sendMessage(configManager.applyPrefix(line));
    }

    private String formatEpochMillis(long millis) {
        if (millis <= 0L) {
            return "-";
        }
        return DATE_TIME_FORMATTER.format(Instant.ofEpochMilli(millis));
    }
}
