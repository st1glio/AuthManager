package me.stiglio.authManager.commands;

import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class LookupCommand implements CommandExecutor, TabCompleter {
    private static final String RED = "\u00A7c";
    private static final String GREEN = "\u00A7a";
    private static final String YELLOW = "\u00A7e";
    private static final String GRAY = "\u00A77";
    private static final String WHITE = "\u00A7f";

    private final AuthService authService;
    private final ConfigManager configManager;

    public LookupCommand(AuthService authService, ConfigManager configManager) {
        this.authService = authService;
        this.configManager = configManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("authmanager.admin")) {
            sender.sendMessage(configManager.getMessage("no-permission"));
            return true;
        }

        if (args.length != 1) {
            sender.sendMessage(configManager.getMessage("usage-lookup"));
            return true;
        }

        String query = args[0];
        sendLine(sender, YELLOW + "Lookup in corso per: " + WHITE + query + GRAY + " ...");
        authService.lookupIpInfoAsync(query, lookup -> {
            if (!lookup.success()) {
                sendLine(sender, RED + "Lookup fallito: " + lookup.note());
                return;
            }

            sendLine(sender, GREEN + "Lookup completato");
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
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission("authmanager.admin")) {
            return List.of();
        }

        if (args.length != 1) {
            return List.of();
        }

        String token = args[0].toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (Player online : Bukkit.getOnlinePlayers()) {
            if (online.getName().toLowerCase(Locale.ROOT).startsWith(token)) {
                out.add(online.getName());
            }
        }
        return out;
    }

    private String blankDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private void sendLine(CommandSender sender, String line) {
        sender.sendMessage(configManager.applyPrefix(line));
    }
}
