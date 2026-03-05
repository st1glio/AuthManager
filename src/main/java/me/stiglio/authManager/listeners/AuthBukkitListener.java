package me.stiglio.authManager.listeners;

import io.papermc.paper.event.player.AsyncChatEvent;
import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.config.ConfigManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.player.PlayerArmorStandManipulateEvent;
import org.bukkit.event.player.PlayerBucketEmptyEvent;
import org.bukkit.event.player.PlayerBucketFillEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerKickEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthBukkitListener implements Listener {
    private final AuthManager plugin;
    private final AuthService authService;
    private final ConfigManager configManager;

    private final Map<UUID, Long> lastBlockedMessage = new ConcurrentHashMap<>();

    public AuthBukkitListener(AuthManager plugin, AuthService authService, ConfigManager configManager) {
        this.plugin = plugin;
        this.authService = authService;
        this.configManager = configManager;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        authService.handleJoin(event.getPlayer());
        if (authService.shouldRestrictPlayer(event.getPlayer())) {
            event.getPlayer().closeInventory();
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        authService.handleQuit(event.getPlayer().getUniqueId());
        lastBlockedMessage.remove(event.getPlayer().getUniqueId());
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onKick(PlayerKickEvent event) {
        String reason = event.reason() == null ? "unknown" : event.reason().toString();
        authService.auditKick(event.getPlayer(), reason);
        authService.handleQuit(event.getPlayer().getUniqueId());
        lastBlockedMessage.remove(event.getPlayer().getUniqueId());
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        if (!configManager.isBlockMovementWhileUnauthed()) {
            return;
        }

        Player player = event.getPlayer();
        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        if (event.getTo() == null) {
            event.setCancelled(true);
            return;
        }

        if (Double.compare(event.getFrom().getX(), event.getTo().getX()) == 0
                && Double.compare(event.getFrom().getY(), event.getTo().getY()) == 0
                && Double.compare(event.getFrom().getZ(), event.getTo().getZ()) == 0) {
            return;
        }

        event.setTo(event.getFrom());
        warnBlocked(player, configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onSwap(PlayerSwapHandItemsEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDamage(EntityDamageByEntityEvent event) {
        if (!(event.getDamager() instanceof Player player)) {
            return;
        }

        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(player, configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onItemConsume(PlayerItemConsumeEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent event) {
        if (!(event.getEntity() instanceof Player player)) {
            return;
        }

        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(player, configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBucketFill(PlayerBucketFillEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBucketEmpty(PlayerBucketEmptyEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onArmorStandManipulate(PlayerArmorStandManipulateEvent event) {
        if (!authService.shouldRestrictPlayer(event.getPlayer())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(event.getPlayer(), configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (!(event.getWhoClicked() instanceof Player player)) {
            return;
        }

        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(player, configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (!(event.getWhoClicked() instanceof Player player)) {
            return;
        }

        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(player, configManager.getMessage("action-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        if (authService.isCommandAllowedWhileUnauthenticated(event.getMessage())) {
            return;
        }

        event.setCancelled(true);
        warnBlocked(player, configManager.getMessage("command-blocked"));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        if (!configManager.isBlockChatWhileUnauthed()) {
            return;
        }

        Player player = event.getPlayer();
        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        event.setCancelled(true);
        Bukkit.getScheduler().runTask(plugin, () -> warnBlocked(player, configManager.getMessage("chat-blocked")));
    }

    private void warnBlocked(Player player, String message) {
        long now = System.currentTimeMillis();
        long previous = lastBlockedMessage.getOrDefault(player.getUniqueId(), 0L);
        if (now - previous < configManager.getBlockedMessageCooldownMillis()) {
            return;
        }

        lastBlockedMessage.put(player.getUniqueId(), now);
        player.sendMessage(message);
    }
}
