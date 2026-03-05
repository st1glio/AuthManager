package me.stiglio.authManager.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountLockManagerTest {

    @Test
    void shouldLockAfterConfiguredFailures() {
        AccountLockManager manager = new AccountLockManager(120, 2, 5, true);

        assertFalse(manager.check("PlayerOne").blocked());
        manager.recordFailure("PlayerOne");
        assertFalse(manager.check("PlayerOne").blocked());

        manager.recordFailure("PlayerOne");
        assertTrue(manager.check("PlayerOne").blocked());
    }

    @Test
    void shouldClearLockAfterSuccess() {
        AccountLockManager manager = new AccountLockManager(120, 1, 5, true);

        manager.recordFailure("PlayerTwo");
        assertTrue(manager.check("PlayerTwo").blocked());

        manager.recordSuccess("PlayerTwo");
        assertFalse(manager.check("PlayerTwo").blocked());
    }

    @Test
    void shouldIgnoreWhenDisabled() {
        AccountLockManager manager = new AccountLockManager(120, 1, 5, false);

        manager.recordFailure("PlayerThree");
        assertFalse(manager.check("PlayerThree").blocked());
    }
}
