
package me.stiglio.authManager.service;

import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.database.UserDAO;
import me.stiglio.authManager.mojang.MojangClient;
import me.stiglio.authManager.mojang.MojangProfile;
import me.stiglio.authManager.models.User;
import me.stiglio.authManager.utils.HashUtils;
import me.stiglio.authManager.utils.MessageUtils;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class AuthService {
    private static final long LOGIN_START_IDENTITY_TTL_MILLIS = 60_000L;
    private static final long PACKET_IDENTITY_TTL_MILLIS = 180_000L;
    private static final int MAX_LOGIN_START_KEYS = 2_048;
    private static final int MAX_LOGIN_START_PER_KEY = 8;

    public enum PendingAuthType {
        LOGIN,
        REGISTER
    }

    private final AuthManager plugin;
    private final ConfigManager configManager;
    private final UserDAO userDAO;
    private final MojangClient mojangClient;
    private final IpIntelligenceClient ipIntelligenceClient;
    private volatile AuthRateLimiter rateLimiter;
    private volatile AccountLockManager accountLockManager;
    private final RememberedSessionStore rememberedSessionStore;
    private final ExecutorService authExecutor;

    private final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private final Map<UUID, PendingAuthType> pendingAuth = new ConcurrentHashMap<>();
    private final Map<UUID, Long> authDeadlines = new ConcurrentHashMap<>();
    private final Map<UUID, PacketLoginIdentity> packetLoginIdentities = new ConcurrentHashMap<>();
    private final Map<String, ConcurrentLinkedDeque<LoginStartIdentity>> pendingLoginStartIdentities = new ConcurrentHashMap<>();

    private int reminderTaskId = -1;
    private int authTimeoutTaskId = -1;
    private int cleanupTaskId = -1;

    public AuthService(AuthManager plugin, ConfigManager configManager, UserDAO userDAO,
                       MojangClient mojangClient, IpIntelligenceClient ipIntelligenceClient) {
        this.plugin = plugin;
        this.configManager = configManager;
        this.userDAO = userDAO;
        this.mojangClient = mojangClient;
        this.ipIntelligenceClient = ipIntelligenceClient;
        this.rateLimiter = buildRateLimiter();
        this.accountLockManager = buildAccountLockManager();
        this.rememberedSessionStore = new RememberedSessionStore();
        this.authExecutor = Executors.newFixedThreadPool(
                configManager.getAuthExecutorThreads(),
                new AuthWorkerThreadFactory()
        );
        logVerificationMode();
    }

    public void startReminderTask() {
        int periodTicks = configManager.getReminderSeconds() * 20;
        reminderTaskId = Bukkit.getScheduler().scheduleSyncRepeatingTask(plugin, () -> {
            for (Player player : Bukkit.getOnlinePlayers()) {
                if (isAuthenticated(player.getUniqueId())) {
                    continue;
                }

                PendingAuthType authType = pendingAuth.getOrDefault(player.getUniqueId(), PendingAuthType.REGISTER);
                if (authType == PendingAuthType.LOGIN) {
                    player.sendMessage(configManager.getMessage("login-required"));
                } else {
                    player.sendMessage(configManager.getMessage("register-required"));
                }
            }
        }, periodTicks, periodTicks);

        authTimeoutTaskId = Bukkit.getScheduler().scheduleSyncRepeatingTask(plugin, () -> {
            long now = System.currentTimeMillis();
            for (Player player : Bukkit.getOnlinePlayers()) {
                UUID playerId = player.getUniqueId();
                if (isAuthenticated(playerId)) {
                    authDeadlines.remove(playerId);
                    continue;
                }

                PendingAuthType pending = pendingAuth.get(playerId);
                if (pending == null) {
                    authDeadlines.remove(playerId);
                    continue;
                }

                long deadline = authDeadlines.computeIfAbsent(playerId,
                        ignored -> now + (configManager.getAuthTimeoutSeconds() * 1000L));
                if (now < deadline) {
                    continue;
                }

                authDeadlines.remove(playerId);
                String kickMessage = configManager.getMessage("auth-timeout-kick",
                        "{seconds}", String.valueOf(configManager.getAuthTimeoutSeconds()));
                player.kick(MessageUtils.toComponent(kickMessage));
                audit("auth_timeout_kick", player.getName(), playerId, extractPlayerIp(player), "timeout");
            }
        }, 20L, 20L);

        cleanupTaskId = Bukkit.getScheduler().scheduleSyncRepeatingTask(plugin, () -> {
            cleanupExpiredLoginStarts(System.currentTimeMillis());
            rememberedSessionStore.cleanupExpired();
            accountLockManager.cleanupExpired();
        }, 20L * 60L, 20L * 60L);
    }

    public void shutdown() {
        authenticatedPlayers.clear();
        pendingAuth.clear();
        authDeadlines.clear();
        packetLoginIdentities.clear();
        pendingLoginStartIdentities.clear();

        if (reminderTaskId != -1) {
            Bukkit.getScheduler().cancelTask(reminderTaskId);
            reminderTaskId = -1;
        }

        if (authTimeoutTaskId != -1) {
            Bukkit.getScheduler().cancelTask(authTimeoutTaskId);
            authTimeoutTaskId = -1;
        }

        if (cleanupTaskId != -1) {
            Bukkit.getScheduler().cancelTask(cleanupTaskId);
            cleanupTaskId = -1;
        }

        accountLockManager.clearAll();
        rememberedSessionStore.clearAll();
        ipIntelligenceClient.clearCache();
        authExecutor.shutdownNow();
        try {
            authExecutor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    public OperationResult validateStartupConfiguration() {
        if (!configManager.isPremiumNameProtectionEnabled()) {
            return new OperationResult(true, "Premium name protection disabled by config.");
        }

        if (!configManager.isPremiumVerificationStrict()) {
            return new OperationResult(true, "Premium verification mode is compatibility.");
        }

        if (canTrustPremiumIdentity()) {
            return new OperationResult(true, "Premium verification strict mode is safely configured.");
        }

        String reason = "Unsafe startup configuration: strict premium verification requires online-mode=true "
                + "or trusted-proxy-premium-identity=true. Current setup is offline-mode without trusted proxy identity.";
        return new OperationResult(false, reason);
    }

    public void reloadRuntimeConfiguration() {
        this.rateLimiter = buildRateLimiter();
        this.rateLimiter.clearAll();
        this.accountLockManager = buildAccountLockManager();
        if (!configManager.isRememberSessionEnabled()) {
            rememberedSessionStore.clearAll();
        }
        ipIntelligenceClient.clearCache();
        if (reminderTaskId != -1 || authTimeoutTaskId != -1) {
            if (reminderTaskId != -1) {
                Bukkit.getScheduler().cancelTask(reminderTaskId);
                reminderTaskId = -1;
            }
            if (authTimeoutTaskId != -1) {
                Bukkit.getScheduler().cancelTask(authTimeoutTaskId);
                authTimeoutTaskId = -1;
            }
            if (cleanupTaskId != -1) {
                Bukkit.getScheduler().cancelTask(cleanupTaskId);
                cleanupTaskId = -1;
            }
            startReminderTask();
        }
        logVerificationMode();
    }

    public OperationResult checkPreLoginRateLimit(String playerName, String ipAddress) {
        if (!configManager.isRateLimitEnabled() || !configManager.isPreLoginRateLimitEnabled()) {
            return new OperationResult(true, "");
        }

        AuthRateLimiter.Decision before = rateLimiter.checkIpOnly(AuthRateLimiter.Action.PRE_LOGIN, ipAddress);
        if (before.blocked()) {
            audit("prelogin_rate_limited", playerName, null, ipAddress, "blocked_existing_cooldown");
            return new OperationResult(false, configManager.getMessage("rate-limit-pre-login-blocked",
                    "{seconds}", String.valueOf(before.secondsLeft())));
        }

        rateLimiter.recordFailureIpOnly(AuthRateLimiter.Action.PRE_LOGIN, ipAddress);
        AuthRateLimiter.Decision after = rateLimiter.checkIpOnly(AuthRateLimiter.Action.PRE_LOGIN, ipAddress);
        if (!after.blocked()) {
            return new OperationResult(true, "");
        }

        audit("prelogin_rate_limited", playerName, null, ipAddress, "burst_detected");
        return new OperationResult(false, configManager.getMessage("rate-limit-pre-login-blocked",
                "{seconds}", String.valueOf(after.secondsLeft())));
    }

    public void resetAllRateLimits() {
        rateLimiter.clearAll();
    }

    public void resetAllSecurityLocks() {
        rateLimiter.clearAll();
        accountLockManager.clearAll();
        rememberedSessionStore.clearAll();
    }

    public AdminStatusSnapshot snapshotStatus() {
        int unauthenticated = 0;
        for (Player online : Bukkit.getOnlinePlayers()) {
            if (shouldRestrictPlayer(online)) {
                unauthenticated++;
            }
        }

        return new AdminStatusSnapshot(
                Bukkit.getOnlineMode(),
                configManager.isPremiumNameProtectionEnabled(),
                configManager.getPremiumVerificationModeNormalized(),
                configManager.isTrustedProxyPremiumIdentity(),
                configManager.isStartupFailFastEnabled(),
                configManager.isRateLimitEnabled(),
                configManager.isPreLoginRateLimitEnabled(),
                unauthenticated,
                Bukkit.getOnlinePlayers().size(),
                rateLimiter.countEntries(AuthRateLimiter.Action.LOGIN),
                rateLimiter.countEntries(AuthRateLimiter.Action.REGISTER),
                rateLimiter.countEntries(AuthRateLimiter.Action.PRE_LOGIN),
                accountLockManager.size(),
                authenticatedPlayers.size(),
                pendingAuth.size(),
                packetLoginIdentities.size(),
                rememberedSessionStore.size()
        );
    }

    public List<UnauthenticatedPlayerSnapshot> snapshotUnauthenticatedPlayers() {
        List<UnauthenticatedPlayerSnapshot> snapshots = new ArrayList<>();
        long now = System.currentTimeMillis();
        for (Player online : Bukkit.getOnlinePlayers()) {
            UUID playerId = online.getUniqueId();
            if (isAuthenticated(playerId)) {
                continue;
            }

            PendingAuthType pending = pendingAuth.getOrDefault(playerId, PendingAuthType.REGISTER);
            long deadline = authDeadlines.getOrDefault(playerId, now);
            long secondsLeft = Math.max(0L, (deadline - now + 999L) / 1000L);
            snapshots.add(new UnauthenticatedPlayerSnapshot(online.getName(), pending, secondsLeft));
        }
        return snapshots;
    }

    public void describeOwnStatusAsync(Player player, Consumer<PlayerStatusSnapshot> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);
        boolean authenticated = isAuthenticated(playerId);
        PendingAuthType pending = pendingAuth.get(playerId);
        long now = System.currentTimeMillis();
        long deadline = authDeadlines.getOrDefault(playerId, now);
        long authSecondsLeft = Math.max(0L, (deadline - now + 999L) / 1000L);
        boolean remembered = rememberedSessionStore.hasValidSession(
                playerName, ip, configManager.isRememberSessionRequireSameIp());
        long rememberedSeconds = rememberedSessionStore.secondsLeft(playerName);
        AccountLockManager.Decision lockDecision = accountLockManager.check(playerName);

        runAsyncTask(() -> userDAO.findByName(playerName).orElse(null), user -> {
            callback.accept(new PlayerStatusSnapshot(
                    playerName,
                    user != null,
                    user != null && user.isPremium(),
                    authenticated,
                    pending,
                    authSecondsLeft,
                    remembered,
                    rememberedSeconds,
                    lockDecision.blocked(),
                    lockDecision.secondsLeft(),
                    user == null ? 0L : user.getLastLoginAt(),
                    user == null ? "" : user.getLastLoginIp()
            ));
        }, error -> callback.accept(new PlayerStatusSnapshot(
                playerName,
                false,
                false,
                authenticated,
                pending,
                authSecondsLeft,
                remembered,
                rememberedSeconds,
                lockDecision.blocked(),
                lockDecision.secondsLeft(),
                0L,
                ""
        )));
    }

    public OperationResult forceAuthenticate(Player target, String actor) {
        UUID targetId = target.getUniqueId();
        markAuthenticated(targetId);
        audit("admin_force_auth", target.getName(), targetId, extractPlayerIp(target), actor);
        return new OperationResult(true, "Player " + target.getName() + " marked as authenticated.");
    }

    public OperationResult forceUnauthenticate(Player target, String actor) {
        UUID targetId = target.getUniqueId();
        markPendingAuthentication(targetId, PendingAuthType.LOGIN);
        clearRememberedSession(target.getName());
        audit("admin_force_unauth", target.getName(), targetId, extractPlayerIp(target), actor);
        return new OperationResult(true, "Player " + target.getName() + " marked as unauthenticated.");
    }

    public int kickUnauthenticatedPlayers(String kickMessage, String actor) {
        int kicked = 0;
        for (Player online : Bukkit.getOnlinePlayers()) {
            if (!shouldRestrictPlayer(online)) {
                continue;
            }

            kicked++;
            audit("admin_kick_unauth", online.getName(), online.getUniqueId(), extractPlayerIp(online), actor);
            online.kick(MessageUtils.toComponent(kickMessage));
        }
        return kicked;
    }

    public OperationResult clearPacketIdentityAdmin(Player target, String actor) {
        clearPacketIdentity(target.getUniqueId());
        audit("admin_packet_clear", target.getName(), target.getUniqueId(), extractPlayerIp(target), actor);
        return new OperationResult(true, "Packet identity cleared for " + target.getName() + ".");
    }

    public OperationResult unlockSecurityState(String playerName, String playerIp, String actor) {
        if (playerName == null || playerName.isBlank()) {
            return new OperationResult(false, "Player name is required.");
        }

        int removed = 0;
        removed += rateLimiter.clearPlayer(playerName);
        if (playerIp != null && !playerIp.isBlank()) {
            removed += rateLimiter.clearIp(playerIp);
        }
        if (accountLockManager.clear(playerName)) {
            removed++;
        }
        if (rememberedSessionStore.clear(playerName)) {
            removed++;
        }

        audit("admin_unlock_security", playerName, null, normalizeIp(playerIp), actor);
        return new OperationResult(true, "Security state reset for " + playerName + " (entries=" + removed + ").");
    }

    public void setPasswordByAdminAsync(String targetName, String newPassword, String actor, Consumer<OperationResult> callback) {
        runAsyncTask(() -> setPasswordByAdminBlocking(targetName, newPassword, actor),
                callback,
                error -> callback.accept(new OperationResult(false,
                        "Password reset failed: " + sanitize(error.getMessage()))));
    }

    public void fetchUserStatisticsAsync(int activeWindowDays, Consumer<DatabaseStatsSnapshot> callback) {
        runAsyncTask(() -> {
            UserDAO.UserStatistics stats = userDAO.fetchStatistics(activeWindowDays).orElse(
                    new UserDAO.UserStatistics(0, 0, 0, 0));
            return new DatabaseStatsSnapshot(
                    stats.totalUsers(),
                    stats.premiumUsers(),
                    stats.activeUsers(),
                    stats.inactiveUsers(),
                    activeWindowDays
            );
        }, callback, error -> callback.accept(new DatabaseStatsSnapshot(0, 0, 0, 0, activeWindowDays)));
    }

    public void lookupIpInfoAsync(String queryOrPlayer, Consumer<IpLookupSnapshot> callback) {
        runAsyncTask(() -> resolveAndLookupIp(queryOrPlayer),
                callback,
                error -> callback.accept(new IpLookupSnapshot(
                        false,
                        queryOrPlayer,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        false,
                        false,
                        false,
                        false,
                        "none",
                        "lookup_error:" + sanitize(error.getMessage())
                )));
    }

    public void describePlayerAsync(String playerName, Consumer<AdminPlayerSnapshot> callback) {
        runAsyncTask(() -> userDAO.findByName(playerName).orElse(null), user -> {
            Player online = Bukkit.getPlayerExact(playerName);
            UUID onlineUuid = online != null ? online.getUniqueId() : null;
            UUID lookupUuid = user != null ? user.getUuid() : onlineUuid;
            PendingAuthType pending = lookupUuid == null ? null : pendingAuth.get(lookupUuid);
            boolean authenticated = lookupUuid != null && authenticatedPlayers.contains(lookupUuid);
            AccountLockManager.Decision lockDecision = accountLockManager.check(playerName);
            callback.accept(new AdminPlayerSnapshot(
                    playerName,
                    lookupUuid,
                    user == null ? null : user.getUsername(),
                    user != null && user.isPremium(),
                    online != null && online.isOnline(),
                    pending,
                    authenticated,
                    user == null ? 0L : user.getCreatedAt(),
                    user == null ? 0L : user.getLastLoginAt(),
                    user == null ? "" : user.getLastLoginIp(),
                    lockDecision.blocked(),
                    lockDecision.secondsLeft(),
                    false,
                    user == null ? "not_registered" : "ok"
            ));
        }, error -> callback.accept(new AdminPlayerSnapshot(playerName, null, null, false,
                false, null, false, 0L, 0L, "", false, 0L, true,
                "lookup_failed:" + error.getMessage())));
    }
    public void trackLoginStartIdentity(String loginName, String loginIp, UUID loginStartUuid) {
        if (loginName == null || loginName.isBlank()) {
            return;
        }

        long now = System.currentTimeMillis();
        if (pendingLoginStartIdentities.size() > MAX_LOGIN_START_KEYS) {
            cleanupExpiredLoginStarts(now);
        }

        String key = loginStartKey(loginName, loginIp);
        ConcurrentLinkedDeque<LoginStartIdentity> identities = pendingLoginStartIdentities.computeIfAbsent(
                key, ignored -> new ConcurrentLinkedDeque<>());
        identities.addLast(new LoginStartIdentity(loginStartUuid, loginName, loginIp, now));
        trimLoginStartQueue(identities, now);

        CompletableFuture.runAsync(() -> mojangClient.lookupPremiumProfileByName(loginName), authExecutor)
                .exceptionally(ignored -> null);
    }

    public void bindPacketIdentityOnUserLogin(UUID playerId, String playerName, UUID fallbackLoginUuid, String loginIp) {
        if (playerId == null || playerName == null || playerName.isBlank()) {
            return;
        }

        LoginStartIdentity loginStartIdentity = pollLoginStartIdentity(playerName, loginIp, fallbackLoginUuid);
        UUID resolvedUuid = fallbackLoginUuid;
        boolean fromLoginStart = false;

        if (loginStartIdentity != null && loginStartIdentity.isFresh() && loginStartIdentity.loginStartUuid() != null) {
            resolvedUuid = loginStartIdentity.loginStartUuid();
            fromLoginStart = true;
        }

        if (resolvedUuid == null) {
            return;
        }

        packetLoginIdentities.put(playerId, new PacketLoginIdentity(
                resolvedUuid,
                playerName,
                loginIp,
                System.currentTimeMillis(),
                fromLoginStart
        ));
    }

    public void clearPacketIdentity(UUID playerId) {
        packetLoginIdentities.remove(playerId);
    }

    public void handleJoin(Player player) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        markPendingAuthentication(playerId, PendingAuthType.REGISTER);

        runAsyncTask(() -> resolveJoin(playerName, ip),
                joinResolution -> {
                    Player online = Bukkit.getPlayer(playerId);
                    if (online == null || !online.isOnline()) {
                        return;
                    }

                    if (joinResolution.autoLoggedIn()) {
                        markAuthenticated(playerId);
                        online.sendMessage(configManager.getMessage("login-success"));
                        audit("auto_login", playerName, playerId, ip, joinResolution.autoLoginReason());
                        return;
                    }

                    markPendingAuthentication(playerId, joinResolution.pendingAuthType());
                    if (joinResolution.pendingAuthType() == PendingAuthType.LOGIN) {
                        online.sendMessage(configManager.getMessage("login-required"));
                    } else {
                        online.sendMessage(configManager.getMessage("register-required"));
                    }
                },
                error -> {
                    Player online = Bukkit.getPlayer(playerId);
                    if (online != null && online.isOnline()) {
                        online.kick(MessageUtils.toComponent(configManager.getMessage("action-blocked")));
                    }
                    plugin.getLogger().warning("Join auth lookup failed for " + playerName + ": " + error.getMessage());
                    audit("join_lookup_error", playerName, playerId, ip, "dao_error");
                });
    }

    public void handleQuit(UUID playerId) {
        authenticatedPlayers.remove(playerId);
        pendingAuth.remove(playerId);
        authDeadlines.remove(playerId);
        packetLoginIdentities.remove(playerId);
    }

    public boolean isAuthenticated(UUID playerId) {
        return authenticatedPlayers.contains(playerId);
    }

    public boolean shouldRestrictPlayer(Player player) {
        return !isAuthenticated(player.getUniqueId());
    }

    public boolean isMovementBlockingEnabled() {
        return configManager.isBlockMovementWhileUnauthed();
    }

    public boolean isChatBlockingEnabled() {
        return configManager.isBlockChatWhileUnauthed();
    }

    public void registerAsync(Player player, String password, String confirmation, Consumer<OperationResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> registerBlocking(playerId, playerName, password, confirmation, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Register operation failed for " + playerName + ": " + error.getMessage());
                    audit("register_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new OperationResult(false, configManager.getMessage("action-blocked")));
                }
        );
    }

    public void loginAsync(Player player, String password, Consumer<LoginAttemptResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> loginBlocking(playerId, playerName, password, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Login operation failed for " + playerName + ": " + error.getMessage());
                    audit("login_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new LoginAttemptResult(false, configManager.getMessage("action-blocked"), false));
                }
        );
    }

    public void changePasswordAsync(Player player, String oldPassword, String newPassword, String confirmation,
                                    Consumer<OperationResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> changePasswordBlocking(playerId, playerName, oldPassword, newPassword, confirmation, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Change password failed for " + playerName + ": " + error.getMessage());
                    audit("change_password_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new OperationResult(false, configManager.getMessage("action-blocked")));
                }
        );
    }

    public void logoutAsync(Player player, Consumer<OperationResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> logoutBlocking(playerId, playerName, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Logout operation failed for " + playerName + ": " + error.getMessage());
                    audit("logout_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new OperationResult(false, configManager.getMessage("action-blocked")));
                }
        );
    }

    public void verifyPremiumOwnershipAsync(Player player, Consumer<OperationResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> verifyPremiumOwnership(playerId, playerName, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Premium verification failed for " + playerName + ": " + error.getMessage());
                    audit("premium_verify_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new OperationResult(false, configManager.getMessage("action-blocked")));
                }
        );
    }

    public void setPremiumAsync(Player player, boolean premium, Consumer<OperationResult> callback) {
        UUID playerId = player.getUniqueId();
        String playerName = player.getName();
        String ip = extractPlayerIp(player);

        runAsyncTask(
                () -> setPremium(playerId, playerName, premium, ip),
                result -> deliverIfOnline(playerId, callback, result),
                error -> {
                    plugin.getLogger().warning("Set premium failed for " + playerName + ": " + error.getMessage());
                    audit("premium_toggle_error", playerName, playerId, ip, "unexpected_error");
                    deliverIfOnline(playerId, callback, new OperationResult(false, configManager.getMessage("action-blocked")));
                }
        );
    }

    public boolean isCommandAllowedWhileUnauthenticated(String commandOrMessage) {
        String label = extractCommandLabel(commandOrMessage);
        if (label.isBlank()) {
            return false;
        }

        return configManager.getAllowedUnauthenticatedCommands().contains(label);
    }
    public OperationResult verifyBeforeJoin(String playerName, String currentIp, UUID preLoginUuid) {
        String safeIp = normalizeIp(currentIp);
        AccountLockManager.Decision accountLockDecision = accountLockManager.check(playerName);
        if (accountLockDecision.blocked()) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "account_locked");
            return new OperationResult(false, configManager.getMessage("account-locked",
                    "{seconds}", String.valueOf(accountLockDecision.secondsLeft())));
        }

        OperationResult ipCheck = verifyIpReputation(playerName, currentIp, preLoginUuid);
        if (!ipCheck.success()) {
            return ipCheck;
        }

        if (!configManager.isPremiumNameProtectionEnabled()) {
            return new OperationResult(true, "");
        }

        boolean strict = configManager.isPremiumVerificationStrict();
        boolean locallyMarkedPremium;
        try {
            locallyMarkedPremium = userDAO.findByName(playerName).map(User::isPremium).orElse(false);
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Pre-login local premium lookup failed for " + playerName + ": " + exception.getMessage());
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "dao_error");
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }

        MojangClient.ProfileLookupResult lookup = mojangClient.lookupPremiumProfileByName(playerName);
        if (lookup.status() == MojangClient.LookupStatus.ERROR) {
            if (strict || locallyMarkedPremium) {
                audit("prelogin_deny", playerName, preLoginUuid, safeIp, "mojang_lookup_error");
                return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
            }

            audit("prelogin_allow_compat", playerName, preLoginUuid, safeIp, "mojang_lookup_error_fail_open");
            return new OperationResult(true, "");
        }

        if (lookup.status() == MojangClient.LookupStatus.NOT_FOUND) {
            if (locallyMarkedPremium) {
                audit("prelogin_deny", playerName, preLoginUuid, safeIp, "local_premium_not_found_on_mojang");
                return new OperationResult(false, configManager.getMessage("premium-verify-local-premium-mojang-missing"));
            }
            return new OperationResult(true, "");
        }

        MojangProfile mojangProfile = lookup.profile().orElse(null);
        if (mojangProfile == null) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "mojang_profile_missing");
            return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
        }

        if (mojangProfile.demo()) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "mojang_demo_account");
            return new OperationResult(false, configManager.getMessage("premium-verify-demo-account"));
        }

        if (!mojangProfile.name().equalsIgnoreCase(playerName)) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "name_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-name-mismatch"));
        }

        if (strict && !canTrustPremiumIdentity()) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "strict_offline_mode");
            return new OperationResult(false, configManager.getMessage("premium-verify-strict-offline"));
        }

        LoginStartIdentity loginStartIdentity = peekLoginStartIdentity(playerName, currentIp);
        if (loginStartIdentity == null) {
            if (Bukkit.getOnlineMode() && preLoginUuid != null && preLoginUuid.equals(mojangProfile.uuid())) {
                return checkSessionProfileForPreLogin(mojangProfile, playerName, preLoginUuid, safeIp, strict);
            }

            if (strict) {
                audit("prelogin_deny", playerName, preLoginUuid, safeIp, "packet_identity_missing");
                return new OperationResult(false, configManager.getMessage("premium-verify-packet-missing"));
            }
            audit("prelogin_allow_compat", playerName, preLoginUuid, safeIp, "packet_identity_missing");
            return new OperationResult(true, "");
        }

        if (!loginStartIdentity.isFresh()) {
            if (strict) {
                audit("prelogin_deny", playerName, preLoginUuid, safeIp, "packet_identity_expired");
                return new OperationResult(false, configManager.getMessage("premium-verify-session-expired"));
            }
            audit("prelogin_allow_compat", playerName, preLoginUuid, safeIp, "packet_identity_expired");
            return new OperationResult(true, "");
        }

        if (currentIp != null && !currentIp.isBlank()
                && loginStartIdentity.loginIp() != null && !loginStartIdentity.loginIp().isBlank()
                && !loginStartIdentity.loginIp().equals(currentIp)) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "ip_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-ip-mismatch"));
        }

        if (loginStartIdentity.loginStartUuid() == null) {
            if (strict || !Bukkit.getOnlineMode()) {
                audit("prelogin_deny", playerName, preLoginUuid, safeIp, "missing_packet_uuid");
                return new OperationResult(false, configManager.getMessage("premium-verify-packet-uuid-missing"));
            }
        } else if (!loginStartIdentity.loginStartUuid().equals(mojangProfile.uuid())) {
            audit("prelogin_deny", playerName, preLoginUuid, safeIp, "uuid_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-uuid-mismatch"));
        }

        return checkSessionProfileForPreLogin(mojangProfile, playerName, preLoginUuid, safeIp, strict);
    }

    public void auditKick(Player player, String reason) {
        audit("player_kick", player.getName(), player.getUniqueId(), extractPlayerIp(player), reason);
    }

    private JoinResolution resolveJoin(String playerName, String ip) {
        User user = userDAO.findByName(playerName).orElse(null);
        if (user == null) {
            return new JoinResolution(PendingAuthType.REGISTER, false, "none");
        }

        if (!user.getUsername().equals(playerName)) {
            userDAO.updateName(user.getUuid(), playerName);
        }

        if (user.isPremium() && configManager.isAutoLoginPremium()) {
            userDAO.updateLastLogin(user.getUuid(), ip);
            rememberSession(playerName, ip);
            return new JoinResolution(PendingAuthType.LOGIN, true, "premium");
        }

        if (configManager.isRememberSessionEnabled()
                && rememberedSessionStore.hasValidSession(playerName, ip, configManager.isRememberSessionRequireSameIp())) {
            userDAO.updateLastLogin(user.getUuid(), ip);
            return new JoinResolution(PendingAuthType.LOGIN, true, "remembered_session");
        }

        return new JoinResolution(PendingAuthType.LOGIN, false, "none");
    }

    private OperationResult registerBlocking(UUID playerId, String playerName, String password, String confirmation, String ip) {
        if (isAuthenticated(playerId)) {
            return new OperationResult(false, configManager.getMessage("already-authenticated"));
        }

        OperationResult passwordPolicy = validatePasswordPolicy(playerName, password, confirmation);
        if (!passwordPolicy.success()) {
            return passwordPolicy;
        }

        AuthRateLimiter.Decision decision = rateLimitDecision(AuthRateLimiter.Action.REGISTER, playerName, ip);
        if (decision.blocked()) {
            audit("register_blocked", playerName, playerId, ip, "rate_limited");
            return rateLimitedMessage(AuthRateLimiter.Action.REGISTER, decision);
        }

        try {
            if (userDAO.findByName(playerName).isPresent()) {
                rateLimiter.recordFailure(AuthRateLimiter.Action.REGISTER, playerName, ip);
                audit("register_fail", playerName, playerId, ip, "already_registered");
                return new OperationResult(false, configManager.getMessage("already-registered"));
            }

            if (configManager.isMultiAccountProtectionEnabled()) {
                int maxAccountsPerIp = configManager.getMaxAccountsPerIp();
                int existingAccountsOnIp = userDAO.countUsersByLastLoginIp(ip);
                if (existingAccountsOnIp >= maxAccountsPerIp) {
                    rateLimiter.recordFailure(AuthRateLimiter.Action.REGISTER, playerName, ip);
                    audit("register_blocked", playerName, playerId, ip,
                            "multi_account_ip_limit_reached:" + existingAccountsOnIp + "/" + maxAccountsPerIp);
                    return new OperationResult(false, configManager.getMessage("register-ip-limit-reached",
                            "{max}", String.valueOf(maxAccountsPerIp)));
                }
            }

            String passwordHash = HashUtils.hashPassword(password);
            boolean created = userDAO.createUser(playerId, playerName, passwordHash, false, ip);
            if (!created) {
                rateLimiter.recordFailure(AuthRateLimiter.Action.REGISTER, playerName, ip);
                audit("register_fail", playerName, playerId, ip, "create_user_failed");
                return new OperationResult(false, configManager.getMessage("already-registered"));
            }

            rateLimiter.recordSuccess(AuthRateLimiter.Action.REGISTER, playerName, ip);
            accountLockManager.recordSuccess(playerName);
            markAuthenticated(playerId);
            rememberSession(playerName, ip);
            audit("register_success", playerName, playerId, ip, "created");
            return new OperationResult(true, configManager.getMessage("register-success"));
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Register DB/hash error for " + playerName + ": " + exception.getMessage());
            audit("register_error", playerName, playerId, ip, "dao_or_hash_error");
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }
    }

    private LoginAttemptResult loginBlocking(UUID playerId, String playerName, String password, String ip) {
        if (isAuthenticated(playerId)) {
            return new LoginAttemptResult(false, configManager.getMessage("already-authenticated"), false);
        }

        AccountLockManager.Decision accountLockDecision = accountLockManager.check(playerName);
        if (accountLockDecision.blocked()) {
            audit("login_blocked", playerName, playerId, ip, "account_locked");
            return new LoginAttemptResult(false, configManager.getMessage("account-locked",
                    "{seconds}", String.valueOf(accountLockDecision.secondsLeft())), true);
        }

        AuthRateLimiter.Decision decision = rateLimitDecision(AuthRateLimiter.Action.LOGIN, playerName, ip);
        if (decision.blocked()) {
            audit("login_blocked", playerName, playerId, ip, "rate_limited");
            return new LoginAttemptResult(false, rateLimitedMessage(AuthRateLimiter.Action.LOGIN, decision).message(), true);
        }

        try {
            User user = userDAO.findByName(playerName).orElse(null);
            if (user == null) {
                rateLimiter.recordFailure(AuthRateLimiter.Action.LOGIN, playerName, ip);
                accountLockManager.recordFailure(playerName);
                audit("login_fail", playerName, playerId, ip, "not_registered");
                return new LoginAttemptResult(false, configManager.getMessage("not-registered"), false);
            }

            if (!HashUtils.checkPassword(password, user.getPasswordHash())) {
                rateLimiter.recordFailure(AuthRateLimiter.Action.LOGIN, playerName, ip);
                accountLockManager.recordFailure(playerName);
                audit("login_fail", playerName, playerId, ip, "invalid_password");
                return new LoginAttemptResult(false, configManager.getMessage("login-failed-kick"), true);
            }

            markAuthenticated(playerId);
            userDAO.updateLastLogin(user.getUuid(), ip);
            rateLimiter.recordSuccess(AuthRateLimiter.Action.LOGIN, playerName, ip);
            accountLockManager.recordSuccess(playerName);
            rememberSession(playerName, ip);
            audit("login_success", playerName, playerId, ip, "password_ok");
            return new LoginAttemptResult(true, configManager.getMessage("login-success"), false);
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Login DB/hash error for " + playerName + ": " + exception.getMessage());
            audit("login_error", playerName, playerId, ip, "dao_or_hash_error");
            return new LoginAttemptResult(false, configManager.getMessage("action-blocked"), false);
        }
    }
    private OperationResult logoutBlocking(UUID playerId, String playerName, String ip) {
        if (!isAuthenticated(playerId)) {
            return new OperationResult(false, configManager.getMessage("not-authenticated"));
        }

        try {
            User user = userDAO.findByName(playerName).orElse(null);
            if (user == null) {
                return new OperationResult(false, configManager.getMessage("not-registered"));
            }

            if (user.isPremium()) {
                return new OperationResult(false, configManager.getMessage("premium-cannot-logout"));
            }

            markPendingAuthentication(playerId, PendingAuthType.LOGIN);
            clearRememberedSession(playerName);
            audit("logout_success", playerName, playerId, ip, "manual_logout");
            return new OperationResult(true, configManager.getMessage("logout-success"));
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Logout DB error for " + playerName + ": " + exception.getMessage());
            audit("logout_error", playerName, playerId, ip, "dao_error");
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }
    }

    private OperationResult changePasswordBlocking(UUID playerId, String playerName, String oldPassword,
                                                   String newPassword, String confirmation, String ip) {
        if (!isAuthenticated(playerId)) {
            return new OperationResult(false, configManager.getMessage("not-authenticated"));
        }

        OperationResult passwordPolicy = validatePasswordPolicy(playerName, newPassword, confirmation);
        if (!passwordPolicy.success()) {
            return passwordPolicy;
        }

        try {
            User user = userDAO.findByName(playerName).orElse(null);
            if (user == null) {
                return new OperationResult(false, configManager.getMessage("not-registered"));
            }

            if (!HashUtils.checkPassword(oldPassword, user.getPasswordHash())) {
                audit("change_password_fail", playerName, playerId, ip, "old_password_invalid");
                return new OperationResult(false, configManager.getMessage("password-old-invalid"));
            }

            if (HashUtils.checkPassword(newPassword, user.getPasswordHash())) {
                return new OperationResult(false, configManager.getMessage("password-same-as-old"));
            }

            String newHash = HashUtils.hashPassword(newPassword);
            boolean updated = userDAO.updatePassword(user.getUuid(), newHash);
            if (!updated) {
                audit("change_password_fail", playerName, playerId, ip, "update_failed");
                return new OperationResult(false, configManager.getMessage("action-blocked"));
            }

            rememberSession(playerName, ip);
            audit("change_password_success", playerName, playerId, ip, "updated");
            return new OperationResult(true, configManager.getMessage("password-changed"));
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Change password DB/hash error for " + playerName + ": " + exception.getMessage());
            audit("change_password_error", playerName, playerId, ip, "dao_or_hash_error");
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }
    }

    private OperationResult verifyPremiumOwnership(UUID playerId, String playerName, String currentIp) {
        PacketLoginIdentity packetIdentity = packetLoginIdentities.get(playerId);
        if (packetIdentity == null) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "packet_identity_missing");
            return new OperationResult(false, configManager.getMessage("premium-verify-packet-missing"));
        }

        if (!packetIdentity.isFresh()) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "packet_identity_expired");
            return new OperationResult(false, configManager.getMessage("premium-verify-session-expired"));
        }

        if (!packetIdentity.loginName().equalsIgnoreCase(playerName)) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "name_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-name-mismatch"));
        }

        if (currentIp != null && !currentIp.isBlank()
                && packetIdentity.loginIp() != null && !packetIdentity.loginIp().isBlank()
                && !packetIdentity.loginIp().equals(currentIp)) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "ip_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-ip-mismatch"));
        }

        boolean strict = configManager.isPremiumVerificationStrict();
        if (strict && !canTrustPremiumIdentity()) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "strict_offline_mode");
            return new OperationResult(false, configManager.getMessage("premium-verify-strict-offline"));
        }

        MojangClient.ProfileLookupResult lookup = mojangClient.lookupPremiumProfileByName(playerName);
        if (lookup.status() == MojangClient.LookupStatus.ERROR) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "mojang_lookup_error");
            return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
        }
        if (lookup.status() == MojangClient.LookupStatus.NOT_FOUND) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "profile_not_found");
            return new OperationResult(false, configManager.getMessage("premium-verify-mojang-not-found"));
        }

        MojangProfile mojangProfile = lookup.profile().orElse(null);
        if (mojangProfile == null) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "profile_missing");
            return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
        }

        if (mojangProfile.demo()) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "demo_account");
            return new OperationResult(false, configManager.getMessage("premium-verify-demo-account"));
        }

        if (!mojangProfile.name().equalsIgnoreCase(playerName)) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "name_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-name-mismatch"));
        }

        if (!packetIdentity.fromLoginStart() && !Bukkit.getOnlineMode()) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "packet_uuid_missing");
            return new OperationResult(false, configManager.getMessage("premium-verify-packet-uuid-missing"));
        }

        if (!packetIdentity.loginUuid().equals(mojangProfile.uuid())) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "uuid_mismatch");
            return new OperationResult(false, configManager.getMessage("premium-verify-uuid-mismatch"));
        }

        MojangClient.SessionValidationResult sessionResult = mojangClient.validateSessionProfile(mojangProfile.uuid());
        if (sessionResult.status() == MojangClient.SessionValidationStatus.ERROR) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "session_api_error");
            return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
        }
        if (sessionResult.status() != MojangClient.SessionValidationStatus.VALID) {
            audit("premium_verify_fail", playerName, playerId, currentIp, "session_invalid");
            return new OperationResult(false, configManager.getMessage("premium-verify-session-failed"));
        }

        if (!strict && !Bukkit.getOnlineMode()) {
            plugin.getLogger().warning("Compatibility premium verification accepted in offline-mode for " + playerName + ". This is best-effort only.");
            audit("premium_verify_warn", playerName, playerId, currentIp, "compatibility_offline_best_effort");
        }

        audit("premium_verify_success", playerName, playerId, currentIp, "verified");
        return new OperationResult(true, configManager.getMessage("premium-verify-success"));
    }

    private OperationResult setPremium(UUID playerId, String playerName, boolean premium, String ip) {
        if (!isAuthenticated(playerId)) {
            return new OperationResult(false, configManager.getMessage("premium-requires-auth"));
        }

        try {
            User user = userDAO.findByName(playerName).orElse(null);
            if (user == null) {
                return new OperationResult(false, configManager.getMessage("not-registered"));
            }

            if (user.isPremium() == premium) {
                return new OperationResult(false, premium
                        ? configManager.getMessage("premium-already-enabled")
                        : configManager.getMessage("premium-already-disabled"));
            }

            if (!userDAO.setPremium(user.getUuid(), premium)) {
                audit("premium_toggle_fail", playerName, playerId, ip, "dao_update_failed");
                return new OperationResult(false, configManager.getMessage("action-blocked"));
            }

            if (premium) {
                rememberSession(playerName, ip);
            }
            audit("premium_toggle_success", playerName, playerId, ip, premium ? "enabled" : "disabled");
            return new OperationResult(true, premium
                    ? configManager.getMessage("premium-enabled")
                    : configManager.getMessage("premium-disabled"));
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Set premium DB error for " + playerName + ": " + exception.getMessage());
            audit("premium_toggle_error", playerName, playerId, ip, "dao_error");
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }
    }

    private OperationResult checkSessionProfileForPreLogin(MojangProfile profile, String playerName,
                                                           UUID preLoginUuid, String currentIp, boolean strict) {
        MojangClient.SessionValidationResult sessionResult = mojangClient.validateSessionProfile(profile.uuid());
        if (sessionResult.status() == MojangClient.SessionValidationStatus.ERROR) {
            if (strict) {
                audit("prelogin_deny", playerName, preLoginUuid, currentIp, "session_api_error");
                return new OperationResult(false, configManager.getMessage("premium-verify-service-unavailable"));
            }
            audit("prelogin_allow_compat", playerName, preLoginUuid, currentIp, "session_api_error_fail_open");
            return new OperationResult(true, "");
        }

        if (sessionResult.status() != MojangClient.SessionValidationStatus.VALID) {
            audit("prelogin_deny", playerName, preLoginUuid, currentIp, "session_invalid");
            return new OperationResult(false, configManager.getMessage("premium-verify-session-failed"));
        }

        if (!strict && !Bukkit.getOnlineMode()) {
            audit("prelogin_warn", playerName, preLoginUuid, currentIp, "compatibility_offline_best_effort");
        }
        return new OperationResult(true, "");
    }

    private LoginStartIdentity pollLoginStartIdentity(String playerName, String loginIp, UUID preferredUuid) {
        LoginStartIdentity match = pollFromQueue(loginStartKey(playerName, loginIp), preferredUuid);
        if (match != null) {
            return match;
        }

        if (loginIp != null && !loginIp.isBlank()) {
            return pollFromQueue(loginStartKey(playerName, ""), preferredUuid);
        }
        return null;
    }

    private LoginStartIdentity pollFromQueue(String key, UUID preferredUuid) {
        ConcurrentLinkedDeque<LoginStartIdentity> queue = pendingLoginStartIdentities.get(key);
        if (queue == null) {
            return null;
        }

        LoginStartIdentity fallback = null;
        long now = System.currentTimeMillis();
        while (true) {
            LoginStartIdentity candidate = queue.pollFirst();
            if (candidate == null) {
                break;
            }
            if (!candidate.isFresh(now)) {
                continue;
            }
            if (preferredUuid != null && candidate.loginStartUuid() != null && !candidate.loginStartUuid().equals(preferredUuid)) {
                if (fallback == null) {
                    fallback = candidate;
                }
                continue;
            }
            if (queue.isEmpty()) {
                pendingLoginStartIdentities.remove(key, queue);
            }
            return candidate;
        }

        if (queue.isEmpty()) {
            pendingLoginStartIdentities.remove(key, queue);
        }
        return fallback;
    }

    private LoginStartIdentity peekLoginStartIdentity(String playerName, String loginIp) {
        String key = loginStartKey(playerName, loginIp);
        ConcurrentLinkedDeque<LoginStartIdentity> queue = pendingLoginStartIdentities.get(key);
        if (queue == null) {
            return null;
        }

        long now = System.currentTimeMillis();
        trimLoginStartQueue(queue, now);
        Iterator<LoginStartIdentity> iterator = queue.descendingIterator();
        while (iterator.hasNext()) {
            LoginStartIdentity candidate = iterator.next();
            if (candidate.isFresh(now)) {
                return candidate;
            }
        }

        if (queue.isEmpty()) {
            pendingLoginStartIdentities.remove(key, queue);
        }
        return null;
    }

    private AuthRateLimiter buildRateLimiter() {
        return new AuthRateLimiter(
                configManager.getRateLimitWindowSeconds(),
                new AuthRateLimiter.Policy(
                        configManager.getLoginRateLimitAttempts(),
                        configManager.getLoginRateLimitBaseCooldownSeconds(),
                        configManager.getLoginRateLimitMaxCooldownSeconds()
                ),
                new AuthRateLimiter.Policy(
                        configManager.getRegisterRateLimitAttempts(),
                        configManager.getRegisterRateLimitBaseCooldownSeconds(),
                        configManager.getRegisterRateLimitMaxCooldownSeconds()
                ),
                new AuthRateLimiter.Policy(
                        configManager.getPreLoginRateLimitAttempts(),
                        configManager.getPreLoginRateLimitBaseCooldownSeconds(),
                        configManager.getPreLoginRateLimitMaxCooldownSeconds()
                )
        );
    }

    private AccountLockManager buildAccountLockManager() {
        return new AccountLockManager(
                configManager.getAccountLockWindowSeconds(),
                configManager.getAccountLockMaxFailures(),
                configManager.getAccountLockSeconds(),
                configManager.isAccountLockEnabled()
        );
    }

    private OperationResult setPasswordByAdminBlocking(String targetName, String newPassword, String actor) {
        OperationResult passwordPolicy = validatePasswordPolicy(targetName, newPassword, newPassword);
        if (!passwordPolicy.success()) {
            return passwordPolicy;
        }

        try {
            User target = userDAO.findByName(targetName).orElse(null);
            if (target == null) {
                return new OperationResult(false, "Target player is not registered.");
            }

            if (HashUtils.checkPassword(newPassword, target.getPasswordHash())) {
                return new OperationResult(false, configManager.getMessage("password-same-as-old"));
            }

            String hash = HashUtils.hashPassword(newPassword);
            if (!userDAO.updatePassword(target.getUuid(), hash)) {
                return new OperationResult(false, configManager.getMessage("action-blocked"));
            }

            accountLockManager.recordSuccess(targetName);
            rateLimiter.clearPlayer(targetName);
            clearRememberedSession(targetName);
            audit("admin_password_reset", targetName, target.getUuid(), target.getLastLoginIp(), actor);
            return new OperationResult(true, "Password updated for " + targetName + ".");
        } catch (RuntimeException exception) {
            plugin.getLogger().warning("Admin password reset failed for " + targetName + ": " + exception.getMessage());
            return new OperationResult(false, configManager.getMessage("action-blocked"));
        }
    }

    private OperationResult validatePasswordPolicy(String playerName, String password, String confirmation) {
        if (password == null || password.isBlank()) {
            return new OperationResult(false, configManager.getMessage("password-too-short",
                    "{min}", String.valueOf(configManager.getMinPasswordLength())));
        }

        if (password.length() < configManager.getMinPasswordLength()) {
            return new OperationResult(false, configManager.getMessage("password-too-short",
                    "{min}", String.valueOf(configManager.getMinPasswordLength())));
        }

        if (password.length() > configManager.getMaxPasswordLength()) {
            return new OperationResult(false, configManager.getMessage("password-too-long",
                    "{max}", String.valueOf(configManager.getMaxPasswordLength())));
        }

        if (confirmation == null || confirmation.isBlank()) {
            return new OperationResult(false, configManager.getMessage("password-confirm-required"));
        }

        if (!password.equals(confirmation)) {
            return new OperationResult(false, configManager.getMessage("password-confirm-mismatch"));
        }

        if (configManager.isPasswordDisallowUsername()
                && playerName != null
                && !playerName.isBlank()
                && password.toLowerCase(Locale.ROOT).contains(playerName.toLowerCase(Locale.ROOT))) {
            return new OperationResult(false, configManager.getMessage("password-contains-username"));
        }

        if (configManager.isPasswordRequireUppercase() && !containsUppercase(password)) {
            return new OperationResult(false, configManager.getMessage("password-missing-uppercase"));
        }

        if (configManager.isPasswordRequireLowercase() && !containsLowercase(password)) {
            return new OperationResult(false, configManager.getMessage("password-missing-lowercase"));
        }

        if (configManager.isPasswordRequireDigit() && !containsDigit(password)) {
            return new OperationResult(false, configManager.getMessage("password-missing-digit"));
        }

        if (configManager.isPasswordRequireSpecial() && !containsSpecial(password)) {
            return new OperationResult(false, configManager.getMessage("password-missing-special"));
        }

        if (configManager.getBlockedPasswords().contains(password.toLowerCase(Locale.ROOT))) {
            return new OperationResult(false, configManager.getMessage("password-too-common"));
        }

        return new OperationResult(true, "");
    }

    private IpLookupSnapshot resolveAndLookupIp(String queryOrPlayer) {
        String requested = queryOrPlayer == null ? "" : queryOrPlayer.trim();
        if (requested.isBlank()) {
            return new IpLookupSnapshot(false, requested, "", "", "", "", "", "", "",
                    "", false, false, false, false, "none", "empty_query");
        }

        String resolvedIp = requested;
        if (!isLikelyIpAddress(resolvedIp)) {
            Player online = Bukkit.getPlayerExact(requested);
            if (online != null && online.getAddress() != null && online.getAddress().getAddress() != null) {
                resolvedIp = online.getAddress().getAddress().getHostAddress();
            } else {
                User stored = userDAO.findByName(requested).orElse(null);
                if (stored != null && stored.getLastLoginIp() != null && !stored.getLastLoginIp().isBlank()) {
                    resolvedIp = stored.getLastLoginIp();
                } else {
                    return new IpLookupSnapshot(false, requested, "", "", "", "", "", "", "",
                            "", false, false, false, false, "none", "player_or_ip_not_found");
                }
            }
        }

        IpIntelligenceClient.LookupResult lookup = ipIntelligenceClient.lookup(resolvedIp);
        return toIpLookupSnapshot(requested, lookup);
    }

    private IpLookupSnapshot toIpLookupSnapshot(String requested, IpIntelligenceClient.LookupResult lookup) {
        return new IpLookupSnapshot(
                lookup.success(),
                requested,
                lookup.resolvedIp(),
                lookup.country(),
                lookup.countryCode(),
                lookup.region(),
                lookup.city(),
                lookup.isp(),
                lookup.organization(),
                lookup.asn(),
                lookup.proxy(),
                lookup.hosting(),
                lookup.mobile(),
                lookup.suspicious(),
                lookup.source(),
                lookup.note()
        );
    }

    private OperationResult verifyIpReputation(String playerName, String currentIp, UUID preLoginUuid) {
        if (!configManager.isIpIntelligenceEnabled() || !configManager.isIpIntelligenceCheckOnPreLogin()) {
            return new OperationResult(true, "");
        }

        if (currentIp == null || currentIp.isBlank()) {
            return new OperationResult(true, "");
        }

        IpIntelligenceClient.LookupResult lookup = ipIntelligenceClient.lookup(currentIp);
        if (!lookup.success()) {
            audit("prelogin_ipintel_error", playerName, preLoginUuid, currentIp, lookup.note());
            if (configManager.isIpIntelligenceFailOpen()) {
                return new OperationResult(true, "");
            }
            return new OperationResult(false, configManager.getMessage("ip-intel-service-unavailable"));
        }

        if (lookup.skippedPrivate()) {
            return new OperationResult(true, "");
        }

        if (configManager.isIpIntelligenceDenyUnknown() && lookup.countryCode().isBlank()) {
            audit("prelogin_ipintel_deny", playerName, preLoginUuid, currentIp, "unknown_country");
            return new OperationResult(false, configManager.getMessage("ip-intel-blocked-unknown"));
        }

        if (configManager.isIpIntelligenceDenyProxy() && lookup.proxy()) {
            audit("prelogin_ipintel_deny", playerName, preLoginUuid, currentIp,
                    "proxy source=" + lookup.source());
            return new OperationResult(false, configManager.getMessage("ip-intel-blocked-proxy"));
        }

        if (configManager.isIpIntelligenceDenyHosting() && lookup.hosting()) {
            audit("prelogin_ipintel_deny", playerName, preLoginUuid, currentIp,
                    "hosting source=" + lookup.source());
            return new OperationResult(false, configManager.getMessage("ip-intel-blocked-hosting"));
        }

        if (configManager.isIpIntelligenceDenyMobile() && lookup.mobile()) {
            audit("prelogin_ipintel_deny", playerName, preLoginUuid, currentIp,
                    "mobile source=" + lookup.source());
            return new OperationResult(false, configManager.getMessage("ip-intel-blocked-mobile"));
        }

        audit("prelogin_ipintel_ok", playerName, preLoginUuid, currentIp,
                "source=" + lookup.source() + " proxy=" + lookup.proxy() + " hosting=" + lookup.hosting());
        return new OperationResult(true, "");
    }

    private void logVerificationMode() {
        if (configManager.isPremiumVerificationStrict()) {
            plugin.getLogger().info("Premium verification mode: strict (fail-closed).");
            if (!canTrustPremiumIdentity()) {
                plugin.getLogger().warning("Offline-mode without trusted proxy identity: strict premium checks can deny joins by design.");
            } else if (!Bukkit.getOnlineMode()) {
                plugin.getLogger().warning("Strict mode with trusted proxy identity enabled. Keep backend reachable only by proxy.");
            }
            return;
        }

        plugin.getLogger().warning("Premium verification mode: compatibility (best-effort). Spoof protection in offline-mode is weaker.");
    }

    private void cleanupExpiredLoginStarts(long now) {
        pendingLoginStartIdentities.entrySet().removeIf(entry -> {
            trimLoginStartQueue(entry.getValue(), now);
            return entry.getValue().isEmpty();
        });
    }

    private void trimLoginStartQueue(ConcurrentLinkedDeque<LoginStartIdentity> queue, long now) {
        while (true) {
            LoginStartIdentity first = queue.peekFirst();
            if (first == null) {
                return;
            }
            if (first.isFresh(now) && queue.size() <= MAX_LOGIN_START_PER_KEY) {
                return;
            }
            queue.pollFirst();
        }
    }

    private AuthRateLimiter.Decision rateLimitDecision(AuthRateLimiter.Action action, String playerName, String ip) {
        if (!configManager.isRateLimitEnabled()) {
            return new AuthRateLimiter.Decision(false, 0L, 0);
        }
        return rateLimiter.check(action, playerName, ip);
    }

    private OperationResult rateLimitedMessage(AuthRateLimiter.Action action, AuthRateLimiter.Decision decision) {
        String key = switch (action) {
            case LOGIN -> "rate-limit-login-blocked";
            case REGISTER -> "rate-limit-register-blocked";
            case PRE_LOGIN -> "rate-limit-pre-login-blocked";
        };
        return new OperationResult(false, configManager.getMessage(key,
                "{seconds}", String.valueOf(decision.secondsLeft()),
                "{attempts}", String.valueOf(decision.attempts())));
    }

    private boolean containsUppercase(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isUpperCase(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    private boolean containsLowercase(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isLowerCase(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    private boolean containsDigit(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isDigit(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    private boolean containsSpecial(String value) {
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!Character.isLetterOrDigit(current)) {
                return true;
            }
        }
        return false;
    }

    private boolean isLikelyIpAddress(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        String trimmed = value.trim();
        if (trimmed.contains(":")) {
            return trimmed.chars().filter(character -> character == ':').count() >= 2;
        }

        String[] parts = trimmed.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isBlank() || part.length() > 3) {
                return false;
            }
            for (int index = 0; index < part.length(); index++) {
                if (!Character.isDigit(part.charAt(index))) {
                    return false;
                }
            }

            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255) {
                return false;
            }
        }
        return true;
    }

    private void markAuthenticated(UUID playerId) {
        authenticatedPlayers.add(playerId);
        pendingAuth.remove(playerId);
        authDeadlines.remove(playerId);
    }

    private void markPendingAuthentication(UUID playerId, PendingAuthType pendingAuthType) {
        authenticatedPlayers.remove(playerId);
        pendingAuth.put(playerId, pendingAuthType);
        startAuthDeadline(playerId);
    }

    private void rememberSession(String playerName, String ip) {
        if (!configManager.isRememberSessionEnabled()) {
            return;
        }
        rememberedSessionStore.remember(playerName, ip, configManager.getRememberSessionDurationMinutes());
    }

    private void clearRememberedSession(String playerName) {
        rememberedSessionStore.clear(playerName);
    }

    private String extractCommandLabel(String commandOrMessage) {
        if (commandOrMessage == null) {
            return "";
        }

        String line = commandOrMessage.trim();
        if (line.startsWith("/")) {
            line = line.substring(1);
        }
        if (line.isBlank()) {
            return "";
        }

        int space = line.indexOf(' ');
        String label = (space == -1 ? line : line.substring(0, space)).toLowerCase(Locale.ROOT);
        if (label.contains(":")) {
            label = label.substring(label.lastIndexOf(':') + 1);
        }
        return label;
    }

    private String loginStartKey(String loginName, String loginIp) {
        return normalizeName(loginName) + "|" + normalizeIp(loginIp);
    }

    private String normalizeName(String loginName) {
        if (loginName == null || loginName.isBlank()) {
            return "unknown";
        }
        return loginName.toLowerCase(Locale.ROOT);
    }

    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "unknown";
        }
        return ip.trim();
    }

    private boolean canTrustPremiumIdentity() {
        if (Bukkit.getOnlineMode()) {
            return true;
        }
        return configManager.isTrustedProxyPremiumIdentity();
    }

    private void startAuthDeadline(UUID playerId) {
        authDeadlines.put(playerId, System.currentTimeMillis() + (configManager.getAuthTimeoutSeconds() * 1000L));
    }

    private String extractPlayerIp(Player player) {
        if (player.getAddress() == null || player.getAddress().getAddress() == null) {
            return "";
        }
        return player.getAddress().getAddress().getHostAddress();
    }

    private <T> void runAsyncTask(Supplier<T> task, Consumer<T> onSuccess, Consumer<Throwable> onError) {
        CompletableFuture.supplyAsync(task, authExecutor)
                .whenComplete((result, throwable) -> {
                    if (!plugin.isEnabled()) {
                        return;
                    }

                    Runnable callback = () -> {
                        if (throwable != null) {
                            onError.accept(unwrapCompletionException(throwable));
                        } else {
                            onSuccess.accept(result);
                        }
                    };

                    if (Bukkit.isPrimaryThread()) {
                        callback.run();
                    } else {
                        Bukkit.getScheduler().runTask(plugin, callback);
                    }
                });
    }

    private Throwable unwrapCompletionException(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && (current instanceof java.util.concurrent.CompletionException
                || current instanceof java.util.concurrent.ExecutionException)) {
            current = current.getCause();
        }
        return current;
    }

    private <T> void deliverIfOnline(UUID playerId, Consumer<T> callback, T payload) {
        Player online = Bukkit.getPlayer(playerId);
        if (online == null || !online.isOnline()) {
            return;
        }
        callback.accept(payload);
    }

    private void audit(String event, String playerName, UUID playerUuid, String ip, String reason) {
        plugin.getLogger().info("AUDIT event=" + sanitize(event)
                + " player=" + sanitize(playerName)
                + " uuid=" + (playerUuid == null ? "-" : playerUuid)
                + " ip=" + sanitize(ip)
                + " reason=" + sanitize(reason));
    }

    private String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value.replace(' ', '_');
    }

    private record LoginStartIdentity(UUID loginStartUuid, String loginName, String loginIp, long capturedAt) {
        private boolean isFresh() {
            return isFresh(System.currentTimeMillis());
        }

        private boolean isFresh(long now) {
            return (now - capturedAt) < LOGIN_START_IDENTITY_TTL_MILLIS;
        }
    }

    private record PacketLoginIdentity(UUID loginUuid, String loginName, String loginIp, long capturedAt, boolean fromLoginStart) {
        private boolean isFresh() {
            return (System.currentTimeMillis() - capturedAt) < PACKET_IDENTITY_TTL_MILLIS;
        }
    }

    public record AdminStatusSnapshot(
            boolean serverOnlineMode,
            boolean premiumNameProtectionEnabled,
            String premiumVerificationMode,
            boolean trustedProxyPremiumIdentity,
            boolean startupFailFast,
            boolean rateLimitEnabled,
            boolean preLoginRateLimitEnabled,
            int unauthenticatedOnline,
            int onlinePlayers,
            int loginRateLimitEntries,
            int registerRateLimitEntries,
            int preLoginRateLimitEntries,
            int accountLockEntries,
            int authenticatedTracked,
            int pendingTracked,
            int packetIdentityTracked,
            int rememberedSessionEntries
    ) {
    }

    public record AdminPlayerSnapshot(
            String requestedName,
            UUID uuid,
            String storedName,
            boolean premium,
            boolean online,
            PendingAuthType pendingAuthType,
            boolean authenticated,
            long createdAt,
            long lastLoginAt,
            String lastLoginIp,
            boolean accountLocked,
            long accountLockSecondsLeft,
            boolean lookupError,
            String note
    ) {
    }

    public record UnauthenticatedPlayerSnapshot(
            String playerName,
            PendingAuthType pendingAuthType,
            long secondsLeft
    ) {
    }

    public record DatabaseStatsSnapshot(
            int totalUsers,
            int premiumUsers,
            int activeUsers,
            int inactiveUsers,
            int activeWindowDays
    ) {
    }

    public record PlayerStatusSnapshot(
            String playerName,
            boolean registered,
            boolean premium,
            boolean authenticated,
            PendingAuthType pendingAuthType,
            long authSecondsLeft,
            boolean rememberedSessionActive,
            long rememberedSessionSecondsLeft,
            boolean accountLocked,
            long accountLockSecondsLeft,
            long lastLoginAt,
            String lastLoginIp
    ) {
    }

    public record IpLookupSnapshot(
            boolean success,
            String requestedQuery,
            String resolvedIp,
            String country,
            String countryCode,
            String region,
            String city,
            String isp,
            String organization,
            String asn,
            boolean proxy,
            boolean hosting,
            boolean mobile,
            boolean suspicious,
            String source,
            String note
    ) {
    }

    private record JoinResolution(PendingAuthType pendingAuthType, boolean autoLoggedIn, String autoLoginReason) {
    }

    private static final class AuthWorkerThreadFactory implements ThreadFactory {
        private final AtomicInteger sequence = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "AuthManager-AuthWorker-" + sequence.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        }
    }
}
