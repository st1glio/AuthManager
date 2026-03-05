package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class ChangePasswordCommand implements CommandExecutor {
    private final AuthService authService;
    private final ConfigManager configManager;

    public ChangePasswordCommand(AuthService authService, ConfigManager configManager) {
        this.authService = authService;
        this.configManager = configManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(configManager.getMessage("player-only"));
            return true;
        }

        if (args.length != 3) {
            player.sendMessage(configManager.getMessage("usage-changepassword"));
            return true;
        }

        authService.changePasswordAsync(player, args[0], args[1], args[2], result -> player.sendMessage(result.message()));
        return true;
    }
}
