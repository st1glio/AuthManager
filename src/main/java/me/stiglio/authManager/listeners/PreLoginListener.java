package me.stiglio.authManager.listeners;

import me.stiglio.authManager.service.AuthService;
import me.stiglio.authManager.service.OperationResult;
import me.stiglio.authManager.utils.MessageUtils;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

public final class PreLoginListener implements Listener {
    private final AuthService authService;

    public PreLoginListener(AuthService authService) {
        this.authService = authService;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        String playerName = event.getName();
        String ip = event.getAddress() != null ? event.getAddress().getHostAddress() : "";

        OperationResult throttle = authService.checkPreLoginRateLimit(playerName, ip);
        if (!throttle.success()) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, MessageUtils.toComponent(throttle.message()));
            return;
        }

        OperationResult result = authService.verifyBeforeJoin(playerName, ip, event.getUniqueId());
        if (!result.success()) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, MessageUtils.toComponent(result.message()));
        }
    }
}
