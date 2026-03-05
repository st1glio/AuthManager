package me.stiglio.authManager.mojang;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class MojangClient {
    private static final Duration PROFILE_CACHE_TTL = Duration.ofMinutes(5);
    private static final Duration SESSION_CACHE_TTL = Duration.ofMinutes(2);

    private final HttpClient httpClient;
    private final ConcurrentHashMap<String, CacheEntry<ProfileLookupResult>> profileCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, CacheEntry<SessionValidationResult>> sessionCache = new ConcurrentHashMap<>();

    public MojangClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public Optional<MojangProfile> findPremiumProfileByName(String username) {
        return lookupPremiumProfileByName(username).profile();
    }

    public ProfileLookupResult lookupPremiumProfileByName(String username) {
        String cacheKey = username.toLowerCase(Locale.ROOT);
        CacheEntry<ProfileLookupResult> cached = profileCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.value();
        }

        ProfileLookupResult resolved = resolveProfile(username);
        profileCache.put(cacheKey, new CacheEntry<>(resolved, Instant.now().plus(PROFILE_CACHE_TTL)));
        return resolved;
    }

    public boolean hasValidSessionProfile(UUID mojangUuid) {
        return validateSessionProfile(mojangUuid).isValid();
    }

    public SessionValidationResult validateSessionProfile(UUID mojangUuid) {
        CacheEntry<SessionValidationResult> cached = sessionCache.get(mojangUuid);
        if (cached != null && !cached.isExpired()) {
            return cached.value();
        }

        SessionValidationResult resolved = resolveSessionProfile(mojangUuid);
        sessionCache.put(mojangUuid, new CacheEntry<>(resolved, Instant.now().plus(SESSION_CACHE_TTL)));
        return resolved;
    }

    private ProfileLookupResult resolveProfile(String username) {
        String encodedName = URLEncoder.encode(username, StandardCharsets.UTF_8);

        ProfileLookupResult viaMinecraftServices = fetchProfile("https://api.minecraftservices.com/minecraft/profile/lookup/name/" + encodedName);
        if (viaMinecraftServices.status() == LookupStatus.FOUND) {
            return viaMinecraftServices;
        }

        ProfileLookupResult viaMojang = fetchProfile("https://api.mojang.com/users/profiles/minecraft/" + encodedName);
        if (viaMojang.status() == LookupStatus.FOUND) {
            return viaMojang;
        }

        if (viaMinecraftServices.status() == LookupStatus.ERROR || viaMojang.status() == LookupStatus.ERROR) {
            return ProfileLookupResult.error();
        }

        return ProfileLookupResult.notFound();
    }

    private ProfileLookupResult fetchProfile(String endpoint) {
        HttpResponse<String> response = sendGet(endpoint);
        if (response == null) {
            return ProfileLookupResult.error();
        }

        int status = response.statusCode();
        if (status == 204 || status == 404) {
            return ProfileLookupResult.notFound();
        }
        if (status != 200) {
            return ProfileLookupResult.error();
        }

        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (!json.has("id") || !json.has("name")) {
                return ProfileLookupResult.error();
            }

            UUID uuid = parseMojangUuid(json.get("id").getAsString());
            String name = json.get("name").getAsString();
            boolean demo = json.has("demo") && json.get("demo").getAsBoolean();
            return ProfileLookupResult.found(new MojangProfile(uuid, name, demo));
        } catch (Exception exception) {
            return ProfileLookupResult.error();
        }
    }

    private SessionValidationResult resolveSessionProfile(UUID mojangUuid) {
        String uuidWithoutDashes = mojangUuid.toString().replace("-", "");
        HttpResponse<String> response = sendGet("https://sessionserver.mojang.com/session/minecraft/profile/" + uuidWithoutDashes + "?unsigned=false");

        if (response == null) {
            return SessionValidationResult.error();
        }

        int status = response.statusCode();
        if (status == 204 || status == 404) {
            return SessionValidationResult.invalid();
        }
        if (status != 200) {
            return SessionValidationResult.error();
        }

        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (!json.has("id")) {
                return SessionValidationResult.invalid();
            }

            UUID receivedUuid = parseMojangUuid(json.get("id").getAsString());
            if (!receivedUuid.equals(mojangUuid)) {
                return SessionValidationResult.invalid();
            }

            if (!json.has("properties") || !json.get("properties").isJsonArray()) {
                return SessionValidationResult.invalid();
            }

            JsonArray properties = json.getAsJsonArray("properties");
            for (JsonElement element : properties) {
                if (!element.isJsonObject()) {
                    continue;
                }

                JsonObject property = element.getAsJsonObject();
                String propertyName = property.has("name") ? property.get("name").getAsString() : "";
                String value = property.has("value") ? property.get("value").getAsString() : "";
                String signature = property.has("signature") ? property.get("signature").getAsString() : "";

                if ("textures".equals(propertyName) && !value.isBlank() && !signature.isBlank()) {
                    return SessionValidationResult.valid();
                }
            }

            return SessionValidationResult.invalid();
        } catch (Exception exception) {
            return SessionValidationResult.error();
        }
    }

    private HttpResponse<String> sendGet(String endpoint) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint))
                .GET()
                .timeout(Duration.ofSeconds(6))
                .header("Accept", "application/json")
                .header("User-Agent", "AuthManager/0.1")
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException exception) {
            return null;
        } catch (Exception exception) {
            return null;
        }
    }

    private UUID parseMojangUuid(String raw) {
        String normalized = raw.replace("-", "");
        if (normalized.length() != 32) {
            throw new IllegalArgumentException("Invalid Mojang UUID format");
        }

        return UUID.fromString(normalized.replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                "$1-$2-$3-$4-$5"));
    }

    private record CacheEntry<T>(T value, Instant expiresAt) {
        private boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    public enum LookupStatus {
        FOUND,
        NOT_FOUND,
        ERROR
    }

    public record ProfileLookupResult(LookupStatus status, Optional<MojangProfile> profile) {
        public static ProfileLookupResult found(MojangProfile profile) {
            return new ProfileLookupResult(LookupStatus.FOUND, Optional.of(profile));
        }

        public static ProfileLookupResult notFound() {
            return new ProfileLookupResult(LookupStatus.NOT_FOUND, Optional.empty());
        }

        public static ProfileLookupResult error() {
            return new ProfileLookupResult(LookupStatus.ERROR, Optional.empty());
        }
    }

    public enum SessionValidationStatus {
        VALID,
        INVALID,
        ERROR
    }

    public record SessionValidationResult(SessionValidationStatus status) {
        public static SessionValidationResult valid() {
            return new SessionValidationResult(SessionValidationStatus.VALID);
        }

        public static SessionValidationResult invalid() {
            return new SessionValidationResult(SessionValidationStatus.INVALID);
        }

        public static SessionValidationResult error() {
            return new SessionValidationResult(SessionValidationStatus.ERROR);
        }

        public boolean isValid() {
            return status == SessionValidationStatus.VALID;
        }
    }
}
