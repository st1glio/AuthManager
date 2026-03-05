package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class RegisterCommand implements CommandExecutor {
    private final AuthService authService;
    private final ConfigManager configManager;

    public RegisterCommand(AuthService authService, ConfigManager configManager) {
        this.authService = authService;
        this.configManager = configManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(configManager.getMessage("player-only"));
            return true;
        }

        if (args.length != 2) {
            player.sendMessage(configManager.getMessage("usage-register"));
            return true;
        }

        authService.registerAsync(player, args[0], args[1], result -> player.sendMessage(result.message()));
        return true;
    }
}
