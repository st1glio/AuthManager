package me.stiglio.authManager;

import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerCommon;
import me.stiglio.authManager.commands.LoginCommand;
import me.stiglio.authManager.commands.PremiumCommand;
import me.stiglio.authManager.commands.RegisterCommand;
import me.stiglio.authManager.commands.UnpremiumCommand;
import me.stiglio.authManager.commands.ChangePasswordCommand;
import me.stiglio.authManager.commands.AuthAdminCommand;
import me.stiglio.authManager.commands.LogoutCommand;
import me.stiglio.authManager.commands.AuthStatusCommand;
import me.stiglio.authManager.commands.LookupCommand;
import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.database.DatabaseManager;
import me.stiglio.authManager.database.UserDAO;
import me.stiglio.authManager.listeners.AuthBukkitListener;
import me.stiglio.authManager.listeners.AuthPacketListener;
import me.stiglio.authManager.listeners.PreLoginListener;
import me.stiglio.authManager.mojang.MojangClient;
import me.stiglio.authManager.service.AuthService;
import me.stiglio.authManager.service.IpIntelligenceClient;
import me.stiglio.authManager.service.OperationResult;
import org.bstats.bukkit.Metrics;
import org.bukkit.Bukkit;
import org.bukkit.command.PluginCommand;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

public final class AuthManager extends JavaPlugin {
    private static final int BSTATS_PLUGIN_ID = 29932;

    private ConfigManager configManager;
    private DatabaseManager databaseManager;
    private AuthService authService;
    private PacketListenerCommon packetListener;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        configManager = new ConfigManager(this);
        configManager.reload();

        new Metrics(this, BSTATS_PLUGIN_ID);

        databaseManager = new DatabaseManager(this, configManager);
        databaseManager.connect();

        UserDAO userDAO = new UserDAO(databaseManager);
        MojangClient mojangClient = new MojangClient();
        IpIntelligenceClient ipIntelligenceClient = new IpIntelligenceClient(configManager);
        authService = new AuthService(this, configManager, userDAO, mojangClient, ipIntelligenceClient);
        OperationResult startupValidation = authService.validateStartupConfiguration();
        if (!startupValidation.success()) {
            if (configManager.isStartupFailFastEnabled()) {
                getLogger().severe(startupValidation.message());
                getLogger().severe("security.startup-fail-fast=true, plugin disabled.");
                Bukkit.getPluginManager().disablePlugin(this);
                return;
            }

            getLogger().warning(startupValidation.message());
            getLogger().warning("Continuing because security.startup-fail-fast=false.");
        }

        registerCommands();
        Bukkit.getPluginManager().registerEvents(new PreLoginListener(authService), this);
        Bukkit.getPluginManager().registerEvents(new AuthBukkitListener(this, authService, configManager), this);

        if (PacketEvents.getAPI() == null) {
            getLogger().warning("PacketEvents API non disponibile: continuo in modalita Bukkit-only.");
        } else if (!PacketEvents.getAPI().isInitialized()) {
            getLogger().warning("PacketEvents API non inizializzata: continuo in modalita Bukkit-only.");
        } else {
            packetListener = PacketEvents.getAPI().getEventManager().registerListener(new AuthPacketListener(this, authService));
        }

        for (Player player : Bukkit.getOnlinePlayers()) {
            authService.handleJoin(player);
        }

        authService.startReminderTask();
        if (packetListener != null) {
            getLogger().info("AuthManager enabled with PacketEvents integration.");
        } else {
            getLogger().info("AuthManager enabled in Bukkit-only restriction mode.");
        }
    }

    @Override
    public void onDisable() {
        if (authService != null) {
            authService.shutdown();
        }

        if (packetListener != null && PacketEvents.getAPI() != null) {
            PacketEvents.getAPI().getEventManager().unregisterListener(packetListener);
        }

        if (databaseManager != null) {
            databaseManager.disconnect();
        }
    }

    public AuthService getAuthService() {
        return authService;
    }

    private void registerCommands() {
        PluginCommand login = getCommand("login");
        PluginCommand register = getCommand("register");
        PluginCommand premium = getCommand("premium");
        PluginCommand unpremium = getCommand("unpremium");
        PluginCommand changePassword = getCommand("changepassword");
        PluginCommand logout = getCommand("logout");
        PluginCommand authAdmin = getCommand("authadmin");
        PluginCommand authStatus = getCommand("authstatus");
        PluginCommand lookup = getCommand("lookup");

        if (login == null || register == null || premium == null || unpremium == null
                || changePassword == null || logout == null || authAdmin == null || authStatus == null || lookup == null) {
            throw new IllegalStateException("Commands are not declared correctly in plugin.yml");
        }

        login.setExecutor(new LoginCommand(authService, configManager));
        register.setExecutor(new RegisterCommand(authService, configManager));
        premium.setExecutor(new PremiumCommand(authService, configManager));
        unpremium.setExecutor(new UnpremiumCommand(authService, configManager));
        changePassword.setExecutor(new ChangePasswordCommand(authService, configManager));
        logout.setExecutor(new LogoutCommand(authService, configManager));
        authStatus.setExecutor(new AuthStatusCommand(authService, configManager));
        LookupCommand lookupExecutor = new LookupCommand(authService, configManager);
        lookup.setExecutor(lookupExecutor);
        lookup.setTabCompleter(lookupExecutor);
        AuthAdminCommand adminExecutor = new AuthAdminCommand(this, authService, configManager);
        authAdmin.setExecutor(adminExecutor);
        authAdmin.setTabCompleter(adminExecutor);
    }
}
