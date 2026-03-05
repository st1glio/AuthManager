package me.stiglio.authManager.commands;

import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import me.stiglio.authManager.service.OperationResult;
import me.stiglio.authManager.utils.MessageUtils;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class AuthAdminCommand implements CommandExecutor, TabCompleter {
    private static final String DARK_GRAY = "\u00A78";
    private static final String GOLD = "\u00A76";
    private static final String RED = "\u00A7c";
    private static final String YELLOW = "\u00A7e";
    private static final String GRAY = "\u00A77";
    private static final String WHITE = "\u00A7f";
    private static final String GREEN = "\u00A7a";
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final AuthManager plugin;
    private final AuthService authService;
    private final ConfigManager configManager;

    public AuthAdminCommand(AuthManager plugin, AuthService authService, ConfigManager configManager) {
        this.plugin = plugin;
        this.authService = authService;
        this.configManager = configManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("authmanager.admin")) {
            sender.sendMessage(configManager.getMessage("no-permission"));
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        return switch (sub) {
            case "help" -> {
                sendHelp(sender);
                yield true;
            }
            case "status" -> {
                handleStatus(sender);
                yield true;
            }
            case "stats" -> {
                handleStats(sender, args);
                yield true;
            }
            case "reload" -> {
                handleReload(sender);
                yield true;
            }
            case "ratelimit" -> {
                handleRateLimit(sender, args);
                yield true;
            }
            case "sessions" -> {
                handleSessions(sender);
                yield true;
            }
            case "unlock" -> {
                handleUnlock(sender, args);
                yield true;
            }
            case "setpassword" -> {
                handleSetPassword(sender, args);
                yield true;
            }
            case "forceauth" -> {
                handleForceAuth(sender, args);
                yield true;
            }
            case "forceunauth" -> {
                handleForceUnauth(sender, args);
                yield true;
            }
            case "kickunauth" -> {
                handleKickUnauth(sender, args);
                yield true;
            }
            case "packet" -> {
                handlePacket(sender, args);
                yield true;
            }
            case "player" -> {
                handlePlayer(sender, args);
                yield true;
            }
            default -> {
                sendLine(sender, RED + "Sottocomando sconosciuto. Usa /" + label + " help");
                yield true;
            }
        };
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission("authmanager.admin")) {
            return List.of();
        }

        if (args.length == 1) {
            return filterPrefix(args[0], List.of(
                    "help", "status", "stats", "reload", "ratelimit", "sessions", "unlock", "setpassword",
                    "forceauth", "forceunauth", "kickunauth", "packet", "player"
            ));
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        if ("ratelimit".equals(sub) && args.length == 2) {
            return filterPrefix(args[1], List.of("status", "clear"));
        }

        if (("forceauth".equals(sub) || "forceunauth".equals(sub)
                || "player".equals(sub) || "unlock".equals(sub) || "setpassword".equals(sub))
                && args.length == 2) {
            return onlinePlayerNames(args[1]);
        }

        if ("packet".equals(sub) && args.length == 2) {
            return filterPrefix(args[1], List.of("clear"));
        }

        if ("packet".equals(sub) && args.length == 3 && "clear".equalsIgnoreCase(args[1])) {
            return onlinePlayerNames(args[2]);
        }

        return List.of();
    }

    private void sendHelp(CommandSender sender) {
        sendLine(sender, YELLOW + "Comandi admin disponibili:");
        sendLine(sender, GRAY + "/authadmin status");
        sendLine(sender, GRAY + "/authadmin stats [giorni_attivi]");
        sendLine(sender, GRAY + "/authadmin reload");
        sendLine(sender, GRAY + "/authadmin ratelimit status");
        sendLine(sender, GRAY + "/authadmin ratelimit clear");
        sendLine(sender, GRAY + "/authadmin sessions");
        sendLine(sender, GRAY + "/authadmin unlock <player>");
        sendLine(sender, GRAY + "/authadmin setpassword <player> <nuovaPassword>");
        sendLine(sender, GRAY + "/authadmin forceauth <player>");
        sendLine(sender, GRAY + "/authadmin forceunauth <player>");
        sendLine(sender, GRAY + "/authadmin kickunauth [messaggio]");
        sendLine(sender, GRAY + "/authadmin packet clear <player>");
        sendLine(sender, GRAY + "/authadmin player <name>");
        sendLine(sender, GRAY + "/lookup <player|ip>");
    }

    private void handleStatus(CommandSender sender) {
        AuthService.AdminStatusSnapshot snapshot = authService.snapshotStatus();
        sendLine(sender, YELLOW + "Status AuthManager:");
        sendLine(sender, GRAY + "online-mode=" + WHITE + snapshot.serverOnlineMode()
                + GRAY + " premium-protection=" + WHITE + snapshot.premiumNameProtectionEnabled());
        sendLine(sender, GRAY + "verification-mode=" + WHITE + snapshot.premiumVerificationMode()
                + GRAY + " trusted-proxy=" + WHITE + snapshot.trustedProxyPremiumIdentity());
        sendLine(sender, GRAY + "startup-fail-fast=" + WHITE + snapshot.startupFailFast());
        sendLine(sender, GRAY + "rate-limit=" + WHITE + snapshot.rateLimitEnabled()
                + GRAY + " pre-login=" + WHITE + snapshot.preLoginRateLimitEnabled());
        sendLine(sender, GRAY + "online=" + WHITE + snapshot.onlinePlayers()
                + GRAY + " unauth=" + WHITE + snapshot.unauthenticatedOnline());
        sendLine(sender, GRAY + "rl-login=" + WHITE + snapshot.loginRateLimitEntries()
                + GRAY + " rl-register=" + WHITE + snapshot.registerRateLimitEntries()
                + GRAY + " rl-prelogin=" + WHITE + snapshot.preLoginRateLimitEntries());
        sendLine(sender, GRAY + "account-lock=" + WHITE + snapshot.accountLockEntries()
                + GRAY + " remembered-sessions=" + WHITE + snapshot.rememberedSessionEntries());
        sendLine(sender, GRAY + "tracked-auth=" + WHITE + snapshot.authenticatedTracked()
                + GRAY + " tracked-pending=" + WHITE + snapshot.pendingTracked()
                + GRAY + " tracked-packet=" + WHITE + snapshot.packetIdentityTracked());
    }

    private void handleStats(CommandSender sender, String[] args) {
        int activeWindowDays = 30;
        if (args.length >= 2) {
            try {
                activeWindowDays = Math.max(1, Integer.parseInt(args[1]));
            } catch (NumberFormatException exception) {
                sendLine(sender, RED + "Uso: /authadmin stats [giorni_attivi]");
                return;
            }
        }

        final int requestedWindowDays = activeWindowDays;
        AuthService.AdminStatusSnapshot runtime = authService.snapshotStatus();
        authService.fetchUserStatisticsAsync(requestedWindowDays, db -> {
            sendLine(sender, YELLOW + "Statistiche account (" + requestedWindowDays + " giorni):");
            sendLine(sender, GRAY + "totali=" + WHITE + db.totalUsers()
                    + GRAY + " premium=" + WHITE + db.premiumUsers());
            sendLine(sender, GRAY + "attivi=" + WHITE + db.activeUsers()
                    + GRAY + " inattivi=" + WHITE + db.inactiveUsers());
            sendLine(sender, GRAY + "online=" + WHITE + runtime.onlinePlayers()
                    + GRAY + " autenticati=" + WHITE + runtime.authenticatedTracked()
                    + GRAY + " in-attesa=" + WHITE + runtime.unauthenticatedOnline());
            sendLine(sender, GRAY + "locks-account=" + WHITE + runtime.accountLockEntries()
                    + GRAY + " remembered-sessions=" + WHITE + runtime.rememberedSessionEntries());
        });
    }

    private void handleReload(CommandSender sender) {
        configManager.reload();
        authService.reloadRuntimeConfiguration();

        OperationResult validation = authService.validateStartupConfiguration();
        if (validation.success()) {
            sendLine(sender, GREEN + "Config ricaricata con successo.");
            return;
        }

        if (configManager.isStartupFailFastEnabled()) {
            sendLine(sender, RED + "Configurazione non sicura: " + validation.message());
            sendLine(sender, RED + "security.startup-fail-fast=true: plugin disabilitato.");
            plugin.getLogger().severe(validation.message());
            Bukkit.getPluginManager().disablePlugin(plugin);
            return;
        }

        sendLine(sender, GOLD + "Configurazione potenzialmente insicura: " + validation.message());
        sendLine(sender, GOLD + "Continuo perche security.startup-fail-fast=false.");
    }

    private void handleRateLimit(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Uso: /authadmin ratelimit <status|clear>");
            return;
        }

        String action = args[1].toLowerCase(Locale.ROOT);
        if ("status".equals(action)) {
            AuthService.AdminStatusSnapshot snapshot = authService.snapshotStatus();
            sendLine(sender, YELLOW + "Rate-limit status:");
            sendLine(sender, GRAY + "enabled=" + WHITE + snapshot.rateLimitEnabled()
                    + GRAY + " pre-login=" + WHITE + snapshot.preLoginRateLimitEnabled());
            sendLine(sender, GRAY + "entries login=" + WHITE + snapshot.loginRateLimitEntries()
                    + GRAY + " register=" + WHITE + snapshot.registerRateLimitEntries()
                    + GRAY + " prelogin=" + WHITE + snapshot.preLoginRateLimitEntries());
            return;
        }

        if ("clear".equals(action)) {
            authService.resetAllSecurityLocks();
            sendLine(sender, GREEN + "Rate-limit e account-lock resettati.");
            return;
        }

        sendLine(sender, RED + "Uso: /authadmin ratelimit <status|clear>");
    }

    private void handleSessions(CommandSender sender) {
        List<AuthService.UnauthenticatedPlayerSnapshot> players = authService.snapshotUnauthenticatedPlayers();
        if (players.isEmpty()) {
            sendLine(sender, GREEN + "Nessun giocatore in attesa di login/register.");
            return;
        }

        sendLine(sender, YELLOW + "Giocatori non autenticati (" + players.size() + "):");
        for (AuthService.UnauthenticatedPlayerSnapshot snapshot : players) {
            sendLine(sender, GRAY + snapshot.playerName()
                    + DARK_GRAY + " | "
                    + GRAY + "step=" + WHITE + snapshot.pendingAuthType()
                    + GRAY + " timeout=" + WHITE + snapshot.secondsLeft() + "s");
        }
    }

    private void handleUnlock(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Uso: /authadmin unlock <player>");
            return;
        }

        String targetName = args[1];
        Player online = Bukkit.getPlayerExact(targetName);
        String ip = "";
        if (online != null && online.getAddress() != null && online.getAddress().getAddress() != null) {
            ip = online.getAddress().getAddress().getHostAddress();
        }

        OperationResult result = authService.unlockSecurityState(targetName, ip, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handleSetPassword(CommandSender sender, String[] args) {
        if (args.length < 3) {
            sendLine(sender, RED + "Uso: /authadmin setpassword <player> <nuovaPassword>");
            return;
        }

        String targetName = args[1];
        String newPassword = args[2];
        authService.setPasswordByAdminAsync(targetName, newPassword, actorName(sender),
                result -> sendLine(sender, colorResult(result)));
    }

    private void handleForceAuth(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Uso: /authadmin forceauth <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sendLine(sender, RED + "Player non trovato online.");
            return;
        }

        OperationResult result = authService.forceAuthenticate(target, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handleForceUnauth(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Uso: /authadmin forceunauth <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sendLine(sender, RED + "Player non trovato online.");
            return;
        }

        OperationResult result = authService.forceUnauthenticate(target, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handleKickUnauth(CommandSender sender, String[] args) {
        String message;
        if (args.length <= 1) {
            message = configManager.getMessage("auth-timeout-kick",
                    "{seconds}", String.valueOf(configManager.getAuthTimeoutSeconds()));
        } else {
            message = MessageUtils.colorizeAmpersand(String.join(" ", slice(args, 1)));
        }

        int kicked = authService.kickUnauthenticatedPlayers(message, actorName(sender));
        sendLine(sender, GREEN + "Giocatori non autenticati kickati: " + kicked);
    }

    private void handlePacket(CommandSender sender, String[] args) {
        if (args.length < 3 || !"clear".equalsIgnoreCase(args[1])) {
            sendLine(sender, RED + "Uso: /authadmin packet clear <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[2]);
        if (target == null) {
            sendLine(sender, RED + "Player non trovato online.");
            return;
        }

        OperationResult result = authService.clearPacketIdentityAdmin(target, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handlePlayer(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Uso: /authadmin player <name>");
            return;
        }

        String playerName = args[1];
        authService.describePlayerAsync(playerName, snapshot -> {
            sendLine(sender, YELLOW + "Player: " + WHITE + snapshot.requestedName());
            sendLine(sender, GRAY + "uuid=" + WHITE + (snapshot.uuid() == null ? "-" : snapshot.uuid()));
            sendLine(sender, GRAY + "stored-name=" + WHITE + (snapshot.storedName() == null ? "-" : snapshot.storedName()));
            sendLine(sender, GRAY + "premium=" + WHITE + snapshot.premium()
                    + GRAY + " online=" + WHITE + snapshot.online());
            sendLine(sender, GRAY + "authenticated=" + WHITE + snapshot.authenticated()
                    + GRAY + " pending=" + WHITE + (snapshot.pendingAuthType() == null ? "-" : snapshot.pendingAuthType().name()));
            sendLine(sender, GRAY + "created-at=" + WHITE + formatEpochMillis(snapshot.createdAt()));
            sendLine(sender, GRAY + "last-login-at=" + WHITE + formatEpochMillis(snapshot.lastLoginAt())
                    + GRAY + " ip=" + WHITE + (snapshot.lastLoginIp().isBlank() ? "-" : snapshot.lastLoginIp()));
            sendLine(sender, GRAY + "account-locked=" + WHITE + snapshot.accountLocked()
                    + GRAY + " remaining=" + WHITE + snapshot.accountLockSecondsLeft() + "s");
            if (snapshot.lookupError()) {
                sendLine(sender, RED + "note=" + snapshot.note());
            } else {
                sendLine(sender, GRAY + "note=" + WHITE + snapshot.note());
            }
        });
    }

    private String colorResult(OperationResult result) {
        String normalized = configManager.stripConfiguredPrefix(result.message());
        return (result.success() ? GREEN : RED) + normalized;
    }

    private String actorName(CommandSender sender) {
        return sender.getName();
    }

    private String[] slice(String[] input, int fromIndex) {
        String[] slice = new String[input.length - fromIndex];
        System.arraycopy(input, fromIndex, slice, 0, slice.length);
        return slice;
    }

    private void sendLine(CommandSender sender, String line) {
        sender.sendMessage(configManager.applyPrefix(line));
    }

    private String formatEpochMillis(long millis) {
        if (millis <= 0L) {
            return "-";
        }
        return DATE_TIME_FORMATTER.format(Instant.ofEpochMilli(millis));
    }

    private List<String> filterPrefix(String token, List<String> options) {
        String lower = token.toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (String option : options) {
            if (option.startsWith(lower)) {
                out.add(option);
            }
        }
        return out;
    }

    private List<String> onlinePlayerNames(String token) {
        String lower = token.toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (Player online : Bukkit.getOnlinePlayers()) {
            if (online.getName().toLowerCase(Locale.ROOT).startsWith(lower)) {
                out.add(online.getName());
            }
        }
        return out;
    }
}
