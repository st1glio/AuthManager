package me.stiglio.authManager.service;

public record LoginAttemptResult(boolean success, String message, boolean shouldKick) {
}
