package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class PremiumCommand implements CommandExecutor {
    private final AuthService authService;
    private final ConfigManager configManager;

    public PremiumCommand(AuthService authService, ConfigManager configManager) {
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
            player.sendMessage(configManager.getMessage("usage-premium"));
            return true;
        }

        if (!authService.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(configManager.getMessage("premium-requires-auth"));
            return true;
        }

        player.sendMessage(configManager.getMessage("premium-verify-in-progress"));
        authService.verifyPremiumOwnershipAsync(player, verification -> {
            if (!verification.success()) {
                player.sendMessage(verification.message());
                return;
            }

            authService.setPremiumAsync(player, true, finalResult -> {
                player.sendMessage(verification.message());
                player.sendMessage(finalResult.message());
            });
        });

        return true;
    }
}
