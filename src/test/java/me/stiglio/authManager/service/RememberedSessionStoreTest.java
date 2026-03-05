package me.stiglio.authManager.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RememberedSessionStoreTest {

    @Test
    void shouldMatchIpWhenRequired() {
        RememberedSessionStore store = new RememberedSessionStore();
        store.remember("PlayerOne", "127.0.0.1", 5);

        assertTrue(store.hasValidSession("PlayerOne", "127.0.0.1", true));
        assertFalse(store.hasValidSession("PlayerOne", "127.0.0.2", true));
    }

    @Test
    void shouldAllowDifferentIpWhenNotRequired() {
        RememberedSessionStore store = new RememberedSessionStore();
        store.remember("PlayerTwo", "127.0.0.1", 5);

        assertTrue(store.hasValidSession("PlayerTwo", "127.0.0.2", false));
    }

    @Test
    void shouldClearSession() {
        RememberedSessionStore store = new RememberedSessionStore();
        store.remember("PlayerThree", "127.0.0.1", 5);
        assertTrue(store.hasValidSession("PlayerThree", "127.0.0.1", true));

        store.clear("PlayerThree");
        assertFalse(store.hasValidSession("PlayerThree", "127.0.0.1", true));
    }
}
