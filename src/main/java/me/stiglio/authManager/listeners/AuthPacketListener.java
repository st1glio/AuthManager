package me.stiglio.authManager.listeners;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.event.UserLoginEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.protocol.packettype.PacketTypeCommon;
import com.github.retrooper.packetevents.wrapper.login.client.WrapperLoginClientLoginStart;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommand;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommandUnsigned;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatMessage;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientPlayerFlying;
import me.stiglio.authManager.AuthManager;
import me.stiglio.authManager.service.AuthService;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.util.Locale;
import java.util.Set;

public final class AuthPacketListener extends PacketListenerAbstract {
    private static final Set<PacketTypeCommon> BLOCKED_PACKET_TYPES = Set.of(
            PacketType.Play.Client.INTERACT_ENTITY,
            PacketType.Play.Client.ANIMATION,
            PacketType.Play.Client.PLAYER_DIGGING,
            PacketType.Play.Client.PLAYER_BLOCK_PLACEMENT,
            PacketType.Play.Client.USE_ITEM,
            PacketType.Play.Client.CREATIVE_INVENTORY_ACTION,
            PacketType.Play.Client.CLICK_WINDOW,
            PacketType.Play.Client.CLICK_WINDOW_BUTTON,
            PacketType.Play.Client.HELD_ITEM_CHANGE,
            PacketType.Play.Client.ENTITY_ACTION,
            PacketType.Play.Client.SPECTATE,
            PacketType.Play.Client.STEER_VEHICLE,
            PacketType.Play.Client.VEHICLE_MOVE,
            PacketType.Play.Client.PLAYER_INPUT,
            PacketType.Play.Client.PICK_ITEM,
            PacketType.Play.Client.PICK_ITEM_FROM_BLOCK,
            PacketType.Play.Client.PICK_ITEM_FROM_ENTITY
    );

    private final AuthManager plugin;
    private final AuthService authService;

    public AuthPacketListener(AuthManager plugin, AuthService authService) {
        super(PacketListenerPriority.HIGHEST);
        this.plugin = plugin;
        this.authService = authService;
    }

    @Override
    public void onUserLogin(UserLoginEvent event) {
        Player player = event.getPlayer();
        if (player == null || event.getUser() == null || event.getUser().getProfile() == null) {
            return;
        }

        String loginIp = "";
        if (event.getUser().getAddress() != null && event.getUser().getAddress().getAddress() != null) {
            loginIp = event.getUser().getAddress().getAddress().getHostAddress();
        }

        authService.bindPacketIdentityOnUserLogin(
                player.getUniqueId(),
                player.getName(),
                event.getUser().getProfile().getUUID(),
                loginIp
        );
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        PacketTypeCommon packetType = event.getPacketType();
        if (packetType == PacketType.Login.Client.LOGIN_START) {
            handleLoginStartPacket(event);
            return;
        }

        Player player = event.getPlayer();
        if (player == null) {
            return;
        }

        if (handlePremiumPacketCommand(event, player)) {
            return;
        }

        if (!authService.shouldRestrictPlayer(player)) {
            return;
        }

        if (packetType == null) {
            return;
        }

        if (WrapperPlayClientPlayerFlying.isFlying(packetType)) {
            if (authService.isMovementBlockingEnabled()) {
                event.setCancelled(true);
            }
            return;
        }

        if (BLOCKED_PACKET_TYPES.contains(packetType)) {
            event.setCancelled(true);
            return;
        }

        if (packetType == PacketType.Play.Client.CHAT_COMMAND) {
            WrapperPlayClientChatCommand wrapper = new WrapperPlayClientChatCommand(event);
            if (!authService.isCommandAllowedWhileUnauthenticated(wrapper.getCommand())) {
                event.setCancelled(true);
            }
            return;
        }

        if (packetType == PacketType.Play.Client.CHAT_COMMAND_UNSIGNED) {
            WrapperPlayClientChatCommandUnsigned wrapper = new WrapperPlayClientChatCommandUnsigned(event);
            if (!authService.isCommandAllowedWhileUnauthenticated(wrapper.getCommand())) {
                event.setCancelled(true);
            }
            return;
        }

        if (packetType == PacketType.Play.Client.CHAT_MESSAGE) {
            if (!authService.isChatBlockingEnabled()) {
                return;
            }

            WrapperPlayClientChatMessage wrapper = new WrapperPlayClientChatMessage(event);
            String message = wrapper.getMessage();
            if (message.startsWith("/") && authService.isCommandAllowedWhileUnauthenticated(message)) {
                return;
            }
            event.setCancelled(true);
        }
    }

    private void handleLoginStartPacket(PacketReceiveEvent event) {
        WrapperLoginClientLoginStart wrapper = new WrapperLoginClientLoginStart(event);
        String username = wrapper.getUsername();
        if (username == null || username.isBlank()) {
            return;
        }

        String loginIp = "";
        if (event.getUser() != null && event.getUser().getAddress() != null && event.getUser().getAddress().getAddress() != null) {
            loginIp = event.getUser().getAddress().getAddress().getHostAddress();
        }

        authService.trackLoginStartIdentity(username, loginIp, wrapper.getPlayerUUID().orElse(null));
    }

    private boolean handlePremiumPacketCommand(PacketReceiveEvent event, Player player) {
        if (authService.shouldRestrictPlayer(player)) {
            return false;
        }

        PacketTypeCommon packetType = event.getPacketType();
        if (packetType == null) {
            return false;
        }

        String rawCommandLine = null;
        if (packetType == PacketType.Play.Client.CHAT_COMMAND) {
            rawCommandLine = new WrapperPlayClientChatCommand(event).getCommand();
        } else if (packetType == PacketType.Play.Client.CHAT_COMMAND_UNSIGNED) {
            rawCommandLine = new WrapperPlayClientChatCommandUnsigned(event).getCommand();
        } else if (packetType == PacketType.Play.Client.CHAT_MESSAGE) {
            String message = new WrapperPlayClientChatMessage(event).getMessage();
            if (message.startsWith("/")) {
                rawCommandLine = message.substring(1);
            }
        }

        if (rawCommandLine == null) {
            return false;
        }

        ParsedCommand parsed = parseCommand(rawCommandLine);
        if (!"premium".equals(parsed.label()) && !"unpremium".equals(parsed.label())) {
            return false;
        }

        event.setCancelled(true);
        String baseCommand = parsed.label();
        String dispatch = parsed.arguments().isBlank() ? baseCommand : baseCommand + " " + parsed.arguments();
        Bukkit.getScheduler().runTask(plugin, () -> {
            Player online = Bukkit.getPlayer(player.getUniqueId());
            if (online != null && online.isOnline()) {
                Bukkit.dispatchCommand(online, dispatch);
            }
        });
        return true;
    }

    private ParsedCommand parseCommand(String commandLine) {
        String line = commandLine == null ? "" : commandLine.trim();
        if (line.startsWith("/")) {
            line = line.substring(1);
        }
        if (line.isBlank()) {
            return new ParsedCommand("", "");
        }

        int space = line.indexOf(' ');
        String label = (space == -1 ? line : line.substring(0, space)).toLowerCase(Locale.ROOT);
        if (label.contains(":")) {
            label = label.substring(label.lastIndexOf(':') + 1);
        }
        String arguments = space == -1 ? "" : line.substring(space + 1).trim();
        return new ParsedCommand(label, arguments);
    }

    private record ParsedCommand(String label, String arguments) {
    }
}
