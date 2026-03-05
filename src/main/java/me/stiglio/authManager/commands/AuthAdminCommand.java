package me.stiglio.authManager.commands;

import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.database.DatabaseManager;
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
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthAdminCommand implements CommandExecutor, TabCompleter {
    private static final String DARK_GRAY = "\u00A78";
    private static final String GOLD = "\u00A76";
    private static final String RED = "\u00A7c";
    private static final String YELLOW = "\u00A7e";
    private static final String GRAY = "\u00A77";
    private static final String WHITE = "\u00A7f";
    private static final String GREEN = "\u00A7a";
    private static final long IMPORT_CONFIRM_TTL_MILLIS = 120_000L;

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final AuthManager plugin;
    private final AuthService authService;
    private final ConfigManager configManager;
    private final Map<String, PendingImportRequest> pendingImports = new ConcurrentHashMap<>();

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
            case "db" -> {
                handleDb(sender, args);
                yield true;
            }
            case "lookup" -> {
                handleLookup(sender, args);
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
                sendLine(sender, RED + "Unknown subcommand. Use /" + label + " help");
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
                    "help", "status", "stats", "db", "lookup", "reload", "ratelimit", "sessions", "unlock",
                    "setpassword", "forceauth", "forceunauth", "kickunauth", "packet", "player"
            ));
        }

        String sub = args[0].toLowerCase(Locale.ROOT);
        if ("ratelimit".equals(sub) && args.length == 2) {
            return filterPrefix(args[1], List.of("status", "clear"));
        }

        if ("db".equals(sub) && args.length == 2) {
            return filterPrefix(args[1], List.of("status", "health", "migrations", "import"));
        }

        if ("db".equals(sub) && args.length == 3 && "import".equalsIgnoreCase(args[1])) {
            return filterPrefix(args[2], List.of("confirm", "cancel", "authmanager.sqlite"));
        }

        if (("lookup".equals(sub) || "forceauth".equals(sub) || "forceunauth".equals(sub)
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
        sendLine(sender, YELLOW + "Available AuthAdmin commands:");
        sendLine(sender, GRAY + "/authadmin status");
        sendLine(sender, GRAY + "/authadmin stats [active_days]");
        sendLine(sender, GRAY + "/authadmin db <status|health|migrations|import>");
        sendLine(sender, GRAY + "/authadmin lookup <player|ip>");
        sendLine(sender, GRAY + "/authadmin reload");
        sendLine(sender, GRAY + "/authadmin ratelimit <status|clear>");
        sendLine(sender, GRAY + "/authadmin sessions");
        sendLine(sender, GRAY + "/authadmin unlock <player>");
        sendLine(sender, GRAY + "/authadmin setpassword <player> <newPassword>");
        sendLine(sender, GRAY + "/authadmin forceauth <player>");
        sendLine(sender, GRAY + "/authadmin forceunauth <player>");
        sendLine(sender, GRAY + "/authadmin kickunauth [message]");
        sendLine(sender, GRAY + "/authadmin packet clear <player>");
        sendLine(sender, GRAY + "/authadmin player <name>");
    }

    private void handleStatus(CommandSender sender) {
        sendLine(sender, YELLOW + "Collecting status snapshot...");
        authService.fetchDetailedStatusAsync(snapshot -> {
            AuthService.AdminStatusSnapshot runtime = snapshot.runtime();
            DatabaseManager.DatabaseHealthSnapshot dbHealth = snapshot.databaseHealth();
            DatabaseManager.DatabaseRuntimeSnapshot dbRuntime = runtime.databaseRuntime();
            DatabaseManager.QueryMetricsSnapshot dbQuery = dbRuntime.queryMetrics();
            DatabaseManager.MigrationSnapshot migrations = dbRuntime.migrations();
            AuthService.MetricsSnapshot login = runtime.loginMetrics();
            AuthService.MetricsSnapshot register = runtime.registerMetrics();
            AuthService.MetricsSnapshot preLogin = runtime.preLoginMetrics();
            AuthService.OnlineUserCacheSnapshot cache = runtime.onlineUserCache();

            sendLine(sender, YELLOW + "AuthManager status:");
            sendLine(sender, GRAY + "uptime=" + WHITE + runtime.uptimeSeconds() + "s"
                    + GRAY + " online-mode=" + WHITE + runtime.serverOnlineMode()
                    + GRAY + " startup-fail-fast=" + WHITE + runtime.startupFailFast());
            sendLine(sender, GRAY + "premium-protection=" + WHITE + runtime.premiumNameProtectionEnabled()
                    + GRAY + " verification=" + WHITE + runtime.premiumVerificationMode()
                    + GRAY + " trusted-proxy=" + WHITE + runtime.trustedProxyPremiumIdentity());
            sendLine(sender, GRAY + "online=" + WHITE + runtime.onlinePlayers()
                    + GRAY + " unauth=" + WHITE + runtime.unauthenticatedOnline()
                    + GRAY + " tracked-auth=" + WHITE + runtime.authenticatedTracked()
                    + GRAY + " tracked-pending=" + WHITE + runtime.pendingTracked());
            sendLine(sender, GRAY + "rate-limit enabled=" + WHITE + runtime.rateLimitEnabled()
                    + GRAY + " pre-login=" + WHITE + runtime.preLoginRateLimitEnabled()
                    + GRAY + " rl(login/register/prelogin)=" + WHITE
                    + runtime.loginRateLimitEntries() + "/"
                    + runtime.registerRateLimitEntries() + "/"
                    + runtime.preLoginRateLimitEntries());
            sendLine(sender, GRAY + "locks=" + WHITE + runtime.accountLockEntries()
                    + GRAY + " remembered-sessions=" + WHITE + runtime.rememberedSessionEntries()
                    + GRAY + " packet-identities=" + WHITE + runtime.packetIdentityTracked());
            sendLine(sender, GRAY + "avg-ms login=" + WHITE + formatDouble(login.averageMillis())
                    + GRAY + " register=" + WHITE + formatDouble(register.averageMillis())
                    + GRAY + " prelogin=" + WHITE + formatDouble(preLogin.averageMillis()));
            sendLine(sender, GRAY + "calls login=" + WHITE + login.totalCalls() + "(" + login.successfulCalls() + "/" + login.failedCalls() + ")"
                    + GRAY + " register=" + WHITE + register.totalCalls() + "(" + register.successfulCalls() + "/" + register.failedCalls() + ")");
            sendLine(sender, GRAY + "db type=" + WHITE + dbRuntime.type()
                    + GRAY + " health=" + WHITE + dbHealth.healthy()
                    + GRAY + " ping=" + WHITE + dbHealth.pingMillis() + "ms"
                    + GRAY + " note=" + WHITE + blankDash(dbHealth.note()));
            sendLine(sender, GRAY + "db pool active/idle/total/waiting=" + WHITE
                    + dbRuntime.activeConnections() + "/"
                    + dbRuntime.idleConnections() + "/"
                    + dbRuntime.totalConnections() + "/"
                    + dbRuntime.threadsAwaitingConnection());
            sendLine(sender, GRAY + "db queries total=" + WHITE + dbQuery.totalQueries()
                    + GRAY + " failed=" + WHITE + dbQuery.failedQueries()
                    + GRAY + " retries=" + WHITE + dbQuery.retriedQueries()
                    + GRAY + " avg-ms=" + WHITE + formatDouble(dbQuery.averageQueryMillis()));
            sendLine(sender, GRAY + "db migrations current/latest=" + WHITE + migrations.currentVersion() + "/" + migrations.latestVersion()
                    + GRAY + " pending=" + WHITE + migrations.pendingVersions().size());
            sendLine(sender, GRAY + "cache entries=" + WHITE + cache.entries()
                    + GRAY + " hits=" + WHITE + cache.hits()
                    + GRAY + " misses=" + WHITE + cache.misses()
                    + GRAY + " hit-rate=" + WHITE + formatDouble(cache.hitRatePercent()) + "%");
            sendLine(sender, GRAY + "executor pool/active/queued=" + WHITE
                    + runtime.authExecutorPoolSize() + "/"
                    + runtime.authExecutorActiveThreads() + "/"
                    + runtime.authExecutorQueuedTasks());
        });
    }

    private void handleStats(CommandSender sender, String[] args) {
        int activeWindowDays = 30;
        if (args.length >= 2) {
            try {
                activeWindowDays = Math.max(1, Integer.parseInt(args[1]));
            } catch (NumberFormatException exception) {
                sendLine(sender, RED + "Usage: /authadmin stats [active_days]");
                return;
            }
        }

        final int requestedWindowDays = activeWindowDays;
        AuthService.AdminStatusSnapshot runtime = authService.snapshotStatus();
        authService.fetchUserStatisticsAsync(requestedWindowDays, db -> {
            sendLine(sender, YELLOW + "Account stats (" + requestedWindowDays + " days):");
            sendLine(sender, GRAY + "total=" + WHITE + db.totalUsers()
                    + GRAY + " premium=" + WHITE + db.premiumUsers());
            sendLine(sender, GRAY + "active=" + WHITE + db.activeUsers()
                    + GRAY + " inactive=" + WHITE + db.inactiveUsers());
            sendLine(sender, GRAY + "online=" + WHITE + runtime.onlinePlayers()
                    + GRAY + " authenticated=" + WHITE + runtime.authenticatedTracked()
                    + GRAY + " pending=" + WHITE + runtime.unauthenticatedOnline());
            sendLine(sender, GRAY + "account-locks=" + WHITE + runtime.accountLockEntries()
                    + GRAY + " remembered-sessions=" + WHITE + runtime.rememberedSessionEntries());
        });
    }

    private void handleDb(CommandSender sender, String[] args) {
        String action = args.length >= 2 ? args[1].toLowerCase(Locale.ROOT) : "status";

        if ("import".equals(action)) {
            handleDbImport(sender, args);
            return;
        }

        authService.fetchDatabaseHealthAsync(health -> {
            DatabaseManager.DatabaseRuntimeSnapshot runtime = health.runtime();
            DatabaseManager.QueryMetricsSnapshot query = runtime.queryMetrics();
            DatabaseManager.MigrationSnapshot migrations = runtime.migrations();

            if ("migrations".equals(action)) {
                sendLine(sender, YELLOW + "Database migrations:");
                sendLine(sender, GRAY + "type=" + WHITE + runtime.type()
                        + GRAY + " current=" + WHITE + migrations.currentVersion()
                        + GRAY + " latest=" + WHITE + migrations.latestVersion());
                sendLine(sender, GRAY + "applied-this-startup=" + WHITE + migrations.appliedThisStartup());
                sendLine(sender, GRAY + "pending=" + WHITE + migrations.pendingVersions());
                return;
            }

            sendLine(sender, YELLOW + "Database health:");
            sendLine(sender, GRAY + "type=" + WHITE + runtime.type()
                    + GRAY + " healthy=" + WHITE + health.healthy()
                    + GRAY + " ping=" + WHITE + health.pingMillis() + "ms"
                    + GRAY + " note=" + WHITE + blankDash(health.note()));
            sendLine(sender, GRAY + "pool active/idle/total/waiting=" + WHITE
                    + runtime.activeConnections() + "/"
                    + runtime.idleConnections() + "/"
                    + runtime.totalConnections() + "/"
                    + runtime.threadsAwaitingConnection());
            sendLine(sender, GRAY + "queries total=" + WHITE + query.totalQueries()
                    + GRAY + " failed=" + WHITE + query.failedQueries()
                    + GRAY + " retries=" + WHITE + query.retriedQueries()
                    + GRAY + " avg-ms=" + WHITE + formatDouble(query.averageQueryMillis()));

            if (!query.topOperations().isEmpty()) {
                sendLine(sender, YELLOW + "Top DB operations:");
                for (DatabaseManager.QueryOperationSnapshot operation : query.topOperations()) {
                    sendLine(sender, GRAY + operation.operation()
                            + DARK_GRAY + " | " + GRAY + "count=" + WHITE + operation.totalQueries()
                            + GRAY + " fail=" + WHITE + operation.failedQueries()
                            + GRAY + " avg-ms=" + WHITE + formatDouble(operation.averageQueryMillis()));
                }
            }
        });
    }

    private void handleDbImport(CommandSender sender, String[] args) {
        if (args.length >= 3) {
            String option = args[2].toLowerCase(Locale.ROOT);
            if ("confirm".equals(option)) {
                PendingImportRequest pending = pendingImports.remove(importKey(sender));
                if (pending == null) {
                    sendLine(sender, RED + "No pending import request. Run /authadmin db import [sqlite-file] first.");
                    return;
                }
                if (!pending.isFresh()) {
                    sendLine(sender, RED + "Pending import expired. Run preview again.");
                    return;
                }

                sendLine(sender, YELLOW + "Starting import from " + WHITE + pending.sourcePath() + YELLOW + " ...");
                authService.runSqliteImportAsync(pending.sourcePath(), result -> {
                    if (!result.success()) {
                        sendLine(sender, RED + "Import failed: " + result.note());
                        return;
                    }
                    sendLine(sender, GREEN + "Import completed.");
                    sendLine(sender, GRAY + "source=" + WHITE + result.sourcePath());
                    sendLine(sender, GRAY + "scanned=" + WHITE + result.scannedRows()
                            + GRAY + " imported=" + WHITE + result.importedRows()
                            + GRAY + " skipped=" + WHITE + result.skippedRows()
                            + GRAY + " failed=" + WHITE + result.failedRows());
                });
                return;
            }

            if ("cancel".equals(option)) {
                pendingImports.remove(importKey(sender));
                sendLine(sender, GREEN + "Pending import cancelled.");
                return;
            }
        }

        String sourcePath = args.length >= 3 ? args[2] : "authmanager.sqlite";
        authService.previewSqliteImportAsync(sourcePath, preview -> {
            if (!preview.ready()) {
                sendLine(sender, RED + "Import preview failed: " + preview.note());
                return;
            }

            String key = importKey(sender);
            pendingImports.put(key, new PendingImportRequest(preview.resolvedPath(), System.currentTimeMillis()));
            sendLine(sender, YELLOW + "Import preview ready:");
            sendLine(sender, GRAY + "source=" + WHITE + preview.resolvedPath());
            sendLine(sender, GRAY + "rows=" + WHITE + preview.totalRows()
                    + GRAY + " invalid-uuid=" + WHITE + preview.invalidUuidRows()
                    + GRAY + " missing-password=" + WHITE + preview.missingPasswordRows());
            sendLine(sender, GOLD + "Confirm within 120s: /authadmin db import confirm");
            sendLine(sender, GRAY + "Cancel: /authadmin db import cancel");
        });
    }

    private void handleLookup(CommandSender sender, String[] args) {
        if (args.length != 2) {
            sendLine(sender, RED + "Usage: /authadmin lookup <player|ip>");
            return;
        }

        String query = args[1];
        sendLine(sender, YELLOW + "Lookup in progress: " + WHITE + query + GRAY + " ...");
        authService.lookupIpInfoAsync(query, lookup -> {
            if (!lookup.success()) {
                sendLine(sender, RED + "Lookup failed: " + lookup.note());
                return;
            }

            sendLine(sender, GREEN + "Lookup completed.");
            sendLine(sender, GRAY + "query=" + WHITE + lookup.requestedQuery()
                    + GRAY + " ip=" + WHITE + blankDash(lookup.resolvedIp()));
            sendLine(sender, GRAY + "country=" + WHITE + blankDash(lookup.country())
                    + GRAY + " code=" + WHITE + blankDash(lookup.countryCode()));
            sendLine(sender, GRAY + "region=" + WHITE + blankDash(lookup.region())
                    + GRAY + " city=" + WHITE + blankDash(lookup.city()));
            sendLine(sender, GRAY + "isp=" + WHITE + blankDash(lookup.isp()));
            sendLine(sender, GRAY + "org=" + WHITE + blankDash(lookup.organization())
                    + GRAY + " asn=" + WHITE + blankDash(lookup.asn()));
            sendLine(sender, GRAY + "proxy=" + WHITE + lookup.proxy()
                    + GRAY + " hosting=" + WHITE + lookup.hosting()
                    + GRAY + " mobile=" + WHITE + lookup.mobile());
            sendLine(sender, GRAY + "suspicious=" + WHITE + lookup.suspicious()
                    + GRAY + " source=" + WHITE + blankDash(lookup.source()));
        });
    }

    private void handleReload(CommandSender sender) {
        configManager.reload();
        authService.reloadRuntimeConfiguration();

        OperationResult validation = authService.validateStartupConfiguration();
        if (validation.success()) {
            sendLine(sender, GREEN + "Configuration reloaded successfully.");
            return;
        }

        if (configManager.isStartupFailFastEnabled()) {
            sendLine(sender, RED + "Unsafe configuration: " + validation.message());
            sendLine(sender, RED + "security.startup-fail-fast=true: disabling plugin.");
            plugin.getLogger().severe(validation.message());
            Bukkit.getPluginManager().disablePlugin(plugin);
            return;
        }

        sendLine(sender, GOLD + "Potentially unsafe configuration: " + validation.message());
        sendLine(sender, GOLD + "Continuing because security.startup-fail-fast=false.");
    }

    private void handleRateLimit(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Usage: /authadmin ratelimit <status|clear>");
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
            sendLine(sender, GREEN + "Rate-limit and account-lock states were reset.");
            return;
        }

        sendLine(sender, RED + "Usage: /authadmin ratelimit <status|clear>");
    }

    private void handleSessions(CommandSender sender) {
        List<AuthService.UnauthenticatedPlayerSnapshot> players = authService.snapshotUnauthenticatedPlayers();
        if (players.isEmpty()) {
            sendLine(sender, GREEN + "No players waiting for login/register.");
            return;
        }

        sendLine(sender, YELLOW + "Unauthenticated players (" + players.size() + "):");
        for (AuthService.UnauthenticatedPlayerSnapshot snapshot : players) {
            sendLine(sender, GRAY + snapshot.playerName()
                    + DARK_GRAY + " | "
                    + GRAY + "step=" + WHITE + snapshot.pendingAuthType()
                    + GRAY + " timeout=" + WHITE + snapshot.secondsLeft() + "s");
        }
    }

    private void handleUnlock(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Usage: /authadmin unlock <player>");
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
            sendLine(sender, RED + "Usage: /authadmin setpassword <player> <newPassword>");
            return;
        }

        String targetName = args[1];
        String newPassword = args[2];
        authService.setPasswordByAdminAsync(targetName, newPassword, actorName(sender),
                result -> sendLine(sender, colorResult(result)));
    }

    private void handleForceAuth(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Usage: /authadmin forceauth <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sendLine(sender, RED + "Player not found online.");
            return;
        }

        OperationResult result = authService.forceAuthenticate(target, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handleForceUnauth(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Usage: /authadmin forceunauth <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[1]);
        if (target == null) {
            sendLine(sender, RED + "Player not found online.");
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
        sendLine(sender, GREEN + "Unauthenticated players kicked: " + kicked);
    }

    private void handlePacket(CommandSender sender, String[] args) {
        if (args.length < 3 || !"clear".equalsIgnoreCase(args[1])) {
            sendLine(sender, RED + "Usage: /authadmin packet clear <player>");
            return;
        }

        Player target = Bukkit.getPlayerExact(args[2]);
        if (target == null) {
            sendLine(sender, RED + "Player not found online.");
            return;
        }

        OperationResult result = authService.clearPacketIdentityAdmin(target, actorName(sender));
        sendLine(sender, colorResult(result));
    }

    private void handlePlayer(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sendLine(sender, RED + "Usage: /authadmin player <name>");
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

    private String blankDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private String formatEpochMillis(long millis) {
        if (millis <= 0L) {
            return "-";
        }
        return DATE_TIME_FORMATTER.format(Instant.ofEpochMilli(millis));
    }

    private String formatDouble(double value) {
        return String.format(Locale.US, "%.2f", value);
    }

    private String importKey(CommandSender sender) {
        if (sender instanceof Player player) {
            UUID id = player.getUniqueId();
            return "player:" + id;
        }
        return "console:" + sender.getName().toLowerCase(Locale.ROOT);
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

    private record PendingImportRequest(String sourcePath, long createdAtMillis) {
        private boolean isFresh() {
            return (System.currentTimeMillis() - createdAtMillis) <= IMPORT_CONFIRM_TTL_MILLIS;
        }
    }
}
