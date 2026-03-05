package me.stiglio.authManager.config;

import me.stiglio.authManager.AuthManager;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import me.stiglio.authManager.utils.MessageUtils;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class ConfigManager {
    private static final int BCRYPT_MAX_PASSWORD_LENGTH = 72;
    private static final String DEFAULT_LANGUAGE = "it";
    private static final String FALLBACK_LANGUAGE = "en";

    private final AuthManager plugin;
    private FileConfiguration config;
    private FileConfiguration messages;
    private FileConfiguration fallbackMessages;
    private String activeLanguage = DEFAULT_LANGUAGE;
    private Set<String> allowedUnauthenticatedCommands = Set.of("login", "register");
    private Set<String> blockedPasswords = Set.of();

    public ConfigManager(AuthManager plugin) {
        this.plugin = plugin;
    }

    public void reload() {
        plugin.reloadConfig();
        this.config = plugin.getConfig();
        applyDefaults();
        loadMessageBundles();
        rebuildRuntimeCache();
        plugin.saveConfig();
    }

    private void applyDefaults() {
        config.addDefault("database-file", "authmanager.sqlite");
        config.addDefault("min-password-length", 6);
        config.addDefault("auto-login-premium", true);
        config.addDefault("auth-reminder-seconds", 6);
        config.addDefault("auth-timeout-seconds", 40);
        config.addDefault("block-chat-while-unauthed", true);
        config.addDefault("block-movement-while-unauthed", true);
        config.addDefault("enforce-premium-name-protection", true);
        config.addDefault("premium-verification-mode", "strict");
        config.addDefault("trusted-proxy-premium-identity", false);
        config.addDefault("auth-executor-threads", 2);
        config.addDefault("auth.blocked-message-cooldown-ms", 1500L);
        config.addDefault("auth.allowed-commands-while-unauthed",
                List.of("login", "register", "authstatus", "l", "reg", "astatus"));

        config.addDefault("session.remember.enabled", false);
        config.addDefault("session.remember.duration-minutes", 30);
        config.addDefault("session.remember.require-same-ip", true);

        config.addDefault("security.account-lock.enabled", true);
        config.addDefault("security.account-lock.window-seconds", 600);
        config.addDefault("security.account-lock.max-failures", 6);
        config.addDefault("security.account-lock.lock-seconds", 180);
        config.addDefault("security.multi-account.enabled", true);
        config.addDefault("security.multi-account.max-accounts-per-ip", 1);

        config.addDefault("security.password.max-length", 64);
        config.addDefault("security.password.require-uppercase", false);
        config.addDefault("security.password.require-lowercase", false);
        config.addDefault("security.password.require-digit", true);
        config.addDefault("security.password.require-special", false);
        config.addDefault("security.password.disallow-username", true);
        config.addDefault("security.password.blocked-list",
                List.of("password", "123456", "qwerty", "password123", "admin123"));
        config.addDefault("security.startup-fail-fast", true);
        config.addDefault("security.ip-intelligence.enabled", true);
        config.addDefault("security.ip-intelligence.check-on-pre-login", true);
        config.addDefault("security.ip-intelligence.skip-private-ip", true);
        config.addDefault("security.ip-intelligence.fail-open", true);
        config.addDefault("security.ip-intelligence.deny-proxy", true);
        config.addDefault("security.ip-intelligence.deny-hosting", true);
        config.addDefault("security.ip-intelligence.deny-mobile", false);
        config.addDefault("security.ip-intelligence.deny-unknown", false);
        config.addDefault("security.ip-intelligence.request-timeout-millis", 2500);
        config.addDefault("security.ip-intelligence.cache-minutes", 20);
        config.addDefault("security.ip-intelligence.ipinfo-token", "0b34ea56fc8ba9");

        config.addDefault("rate-limit.enabled", true);
        config.addDefault("rate-limit.window-seconds", 180);
        config.addDefault("rate-limit.login.max-attempts", 3);
        config.addDefault("rate-limit.login.base-cooldown-seconds", 4);
        config.addDefault("rate-limit.login.max-cooldown-seconds", 60);
        config.addDefault("rate-limit.register.max-attempts", 4);
        config.addDefault("rate-limit.register.base-cooldown-seconds", 6);
        config.addDefault("rate-limit.register.max-cooldown-seconds", 90);
        config.addDefault("rate-limit.pre-login.enabled", true);
        config.addDefault("rate-limit.pre-login.max-attempts", 12);
        config.addDefault("rate-limit.pre-login.base-cooldown-seconds", 2);
        config.addDefault("rate-limit.pre-login.max-cooldown-seconds", 25);
        config.addDefault("language", DEFAULT_LANGUAGE);

        config.options().copyDefaults(true);
    }

    private void rebuildRuntimeCache() {
        Set<String> allowed = new HashSet<>();
        for (String raw : config.getStringList("auth.allowed-commands-while-unauthed")) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            allowed.add(raw.toLowerCase(Locale.ROOT));
        }
        if (allowed.isEmpty()) {
            allowed.add("login");
            allowed.add("register");
        }
        this.allowedUnauthenticatedCommands = Collections.unmodifiableSet(allowed);

        Set<String> blocked = new HashSet<>();
        for (String raw : config.getStringList("security.password.blocked-list")) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            blocked.add(raw.toLowerCase(Locale.ROOT));
        }
        this.blockedPasswords = Collections.unmodifiableSet(blocked);
    }

    public String getDatabaseFile() {
        return config.getString("database-file", "authmanager.sqlite");
    }

    public int getMinPasswordLength() {
        return Math.max(4, config.getInt("min-password-length", 6));
    }

    public int getMaxPasswordLength() {
        int configured = config.getInt("security.password.max-length", 64);
        int clamped = Math.max(getMinPasswordLength(), configured);
        return Math.min(BCRYPT_MAX_PASSWORD_LENGTH, clamped);
    }

    public boolean isPasswordRequireUppercase() {
        return config.getBoolean("security.password.require-uppercase", false);
    }

    public boolean isPasswordRequireLowercase() {
        return config.getBoolean("security.password.require-lowercase", false);
    }

    public boolean isPasswordRequireDigit() {
        return config.getBoolean("security.password.require-digit", true);
    }

    public boolean isPasswordRequireSpecial() {
        return config.getBoolean("security.password.require-special", false);
    }

    public boolean isPasswordDisallowUsername() {
        return config.getBoolean("security.password.disallow-username", true);
    }

    public Set<String> getBlockedPasswords() {
        return blockedPasswords;
    }

    public boolean isAutoLoginPremium() {
        return config.getBoolean("auto-login-premium", true);
    }

    public long getBlockedMessageCooldownMillis() {
        long configured = config.getLong("auth.blocked-message-cooldown-ms", 1500L);
        return Math.max(250L, configured);
    }

    public Set<String> getAllowedUnauthenticatedCommands() {
        return allowedUnauthenticatedCommands;
    }

    public boolean isRememberSessionEnabled() {
        return config.getBoolean("session.remember.enabled", false);
    }

    public int getRememberSessionDurationMinutes() {
        return Math.max(1, config.getInt("session.remember.duration-minutes", 30));
    }

    public boolean isRememberSessionRequireSameIp() {
        return config.getBoolean("session.remember.require-same-ip", true);
    }

    public boolean isAccountLockEnabled() {
        return config.getBoolean("security.account-lock.enabled", true);
    }

    public int getAccountLockWindowSeconds() {
        return Math.max(30, config.getInt("security.account-lock.window-seconds", 600));
    }

    public int getAccountLockMaxFailures() {
        return Math.max(1, config.getInt("security.account-lock.max-failures", 6));
    }

    public int getAccountLockSeconds() {
        return Math.max(1, config.getInt("security.account-lock.lock-seconds", 180));
    }

    public boolean isMultiAccountProtectionEnabled() {
        return config.getBoolean("security.multi-account.enabled", true);
    }

    public int getMaxAccountsPerIp() {
        return Math.max(1, config.getInt("security.multi-account.max-accounts-per-ip", 1));
    }

    public int getReminderSeconds() {
        return Math.max(2, config.getInt("auth-reminder-seconds", 6));
    }

    public int getAuthTimeoutSeconds() {
        return Math.max(10, config.getInt("auth-timeout-seconds", 40));
    }

    public boolean isBlockChatWhileUnauthed() {
        return config.getBoolean("block-chat-while-unauthed", true);
    }

    public boolean isBlockMovementWhileUnauthed() {
        return config.getBoolean("block-movement-while-unauthed", true);
    }

    public boolean isPremiumNameProtectionEnabled() {
        return config.getBoolean("enforce-premium-name-protection", true);
    }

    public String getPremiumVerificationModeRaw() {
        return config.getString("premium-verification-mode", "strict");
    }

    public boolean isPremiumVerificationStrict() {
        String mode = getPremiumVerificationModeRaw();
        return !"compatibility".equalsIgnoreCase(mode);
    }

    public boolean isTrustedProxyPremiumIdentity() {
        return config.getBoolean("trusted-proxy-premium-identity", false);
    }

    public int getAuthExecutorThreads() {
        return Math.max(1, config.getInt("auth-executor-threads", 2));
    }

    public boolean isStartupFailFastEnabled() {
        return config.getBoolean("security.startup-fail-fast", true);
    }

    public boolean isIpIntelligenceEnabled() {
        return config.getBoolean("security.ip-intelligence.enabled", true);
    }

    public boolean isIpIntelligenceCheckOnPreLogin() {
        return config.getBoolean("security.ip-intelligence.check-on-pre-login", true);
    }

    public boolean isIpIntelligenceSkipPrivateIp() {
        return config.getBoolean("security.ip-intelligence.skip-private-ip", true);
    }

    public boolean isIpIntelligenceFailOpen() {
        return config.getBoolean("security.ip-intelligence.fail-open", true);
    }

    public boolean isIpIntelligenceDenyProxy() {
        return config.getBoolean("security.ip-intelligence.deny-proxy", true);
    }

    public boolean isIpIntelligenceDenyHosting() {
        return config.getBoolean("security.ip-intelligence.deny-hosting", true);
    }

    public boolean isIpIntelligenceDenyMobile() {
        return config.getBoolean("security.ip-intelligence.deny-mobile", false);
    }

    public boolean isIpIntelligenceDenyUnknown() {
        return config.getBoolean("security.ip-intelligence.deny-unknown", false);
    }

    public int getIpIntelligenceRequestTimeoutMillis() {
        return Math.max(500, config.getInt("security.ip-intelligence.request-timeout-millis", 2500));
    }

    public int getIpIntelligenceCacheMinutes() {
        return Math.max(1, config.getInt("security.ip-intelligence.cache-minutes", 20));
    }

    public String getIpInfoToken() {
        return config.getString("security.ip-intelligence.ipinfo-token", "").trim();
    }

    public boolean isRateLimitEnabled() {
        return config.getBoolean("rate-limit.enabled", true);
    }

    public int getRateLimitWindowSeconds() {
        return Math.max(30, config.getInt("rate-limit.window-seconds", 180));
    }

    public int getLoginRateLimitAttempts() {
        return Math.max(1, config.getInt("rate-limit.login.max-attempts", 3));
    }

    public int getLoginRateLimitBaseCooldownSeconds() {
        return Math.max(1, config.getInt("rate-limit.login.base-cooldown-seconds", 4));
    }

    public int getLoginRateLimitMaxCooldownSeconds() {
        return Math.max(getLoginRateLimitBaseCooldownSeconds(), config.getInt("rate-limit.login.max-cooldown-seconds", 60));
    }

    public int getRegisterRateLimitAttempts() {
        return Math.max(1, config.getInt("rate-limit.register.max-attempts", 4));
    }

    public int getRegisterRateLimitBaseCooldownSeconds() {
        return Math.max(1, config.getInt("rate-limit.register.base-cooldown-seconds", 6));
    }

    public int getRegisterRateLimitMaxCooldownSeconds() {
        return Math.max(getRegisterRateLimitBaseCooldownSeconds(), config.getInt("rate-limit.register.max-cooldown-seconds", 90));
    }

    public boolean isPreLoginRateLimitEnabled() {
        return config.getBoolean("rate-limit.pre-login.enabled", true);
    }

    public int getPreLoginRateLimitAttempts() {
        return Math.max(1, config.getInt("rate-limit.pre-login.max-attempts", 12));
    }

    public int getPreLoginRateLimitBaseCooldownSeconds() {
        return Math.max(1, config.getInt("rate-limit.pre-login.base-cooldown-seconds", 2));
    }

    public int getPreLoginRateLimitMaxCooldownSeconds() {
        return Math.max(getPreLoginRateLimitBaseCooldownSeconds(), config.getInt("rate-limit.pre-login.max-cooldown-seconds", 25));
    }

    public String getMessage(String key) {
        return getPrefix() + colorize(resolveMessage(key));
    }

    public String getMessage(String key, String... placeholdersAndValues) {
        String text = resolveMessage(key);
        for (int index = 0; index + 1 < placeholdersAndValues.length; index += 2) {
            text = text.replace(placeholdersAndValues[index], placeholdersAndValues[index + 1]);
        }
        return getPrefix() + colorize(text);
    }

    public String getPrefix() {
        return colorize(resolveMessage("prefix"));
    }

    public String applyPrefix(String text) {
        String safeText = text == null ? "" : text;
        return getPrefix() + safeText;
    }

    public String stripConfiguredPrefix(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }

        String prefix = getPrefix();
        if (prefix.isBlank()) {
            return text;
        }
        if (text.startsWith(prefix)) {
            return text.substring(prefix.length());
        }
        return text;
    }

    public String getPremiumVerificationModeNormalized() {
        return getPremiumVerificationModeRaw().toLowerCase(Locale.ROOT);
    }

    private void loadMessageBundles() {
        String configuredLanguage = normalizeLanguage(config.getString("language", DEFAULT_LANGUAGE));
        String fallbackLanguage = configuredLanguage.equals(DEFAULT_LANGUAGE) ? FALLBACK_LANGUAGE : DEFAULT_LANGUAGE;

        config.set("language", configuredLanguage);
        ensureLanguageResource(configuredLanguage);
        ensureLanguageResource(fallbackLanguage);

        this.messages = loadMessageFile(configuredLanguage);
        this.fallbackMessages = configuredLanguage.equals(fallbackLanguage)
                ? this.messages
                : loadMessageFile(fallbackLanguage);
        this.activeLanguage = configuredLanguage;
    }

    private void ensureLanguageResource(String language) {
        String fileName = "messages_" + language + ".yml";
        File target = new File(plugin.getDataFolder(), fileName);
        if (target.exists()) {
            return;
        }

        try {
            plugin.saveResource(fileName, false);
        } catch (IllegalArgumentException exception) {
            plugin.getLogger().warning("Missing bundled language file: " + fileName);
        }
    }

    private FileConfiguration loadMessageFile(String language) {
        String fileName = "messages_" + language + ".yml";
        File target = new File(plugin.getDataFolder(), fileName);
        if (!target.exists()) {
            return new YamlConfiguration();
        }
        return YamlConfiguration.loadConfiguration(target);
    }

    private String resolveMessage(String key) {
        String path = "messages." + key;
        String value = readMessage(this.messages, path);
        if (value.isBlank()) {
            value = readMessage(this.fallbackMessages, path);
        }
        if (value.isBlank()) {
            value = config.getString(path, "");
        }
        if (value == null || value.isBlank()) {
            return "&c<missing message: " + key + ">";
        }
        return value;
    }

    private String readMessage(FileConfiguration source, String path) {
        if (source == null) {
            return "";
        }
        String value = source.getString(path, "");
        return value == null ? "" : value;
    }

    private String normalizeLanguage(String language) {
        if (language == null || language.isBlank()) {
            return DEFAULT_LANGUAGE;
        }

        String normalized = language.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("it")) {
            return "it";
        }
        if (normalized.startsWith("en")) {
            return "en";
        }
        return DEFAULT_LANGUAGE;
    }

    private String colorize(String text) {
        return MessageUtils.colorizeAmpersand(text);
    }
}
