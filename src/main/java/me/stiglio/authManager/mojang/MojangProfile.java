package me.stiglio.authManager.mojang;

import java.util.UUID;

public record MojangProfile(UUID uuid, String name, boolean demo) {
}
