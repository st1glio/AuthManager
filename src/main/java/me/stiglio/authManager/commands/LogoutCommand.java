package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class LogoutCommand implements CommandExecutor {
    private final AuthService authService;
    private final ConfigManager configManager;

    public LogoutCommand(AuthService authService, ConfigManager configManager) {
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
            player.sendMessage(configManager.getMessage("usage-logout"));
            return true;
        }

        authService.logoutAsync(player, result -> player.sendMessage(result.message()));
        return true;
    }
}
