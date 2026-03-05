package me.stiglio.authManager.service;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import me.stiglio.authManager.config.ConfigManager;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class IpIntelligenceClient {
    private static final String IP_API_BASE = "http://ip-api.com/json/";
    private static final String IPINFO_BASE = "https://api.ipinfo.io/lite/";

    private final ConfigManager configManager;
    private final HttpClient httpClient;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public IpIntelligenceClient(ConfigManager configManager) {
        this.configManager = configManager;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(configManager.getIpIntelligenceRequestTimeoutMillis()))
                .build();
    }

    public LookupResult lookup(String query) {
        String normalized = normalizeQuery(query);
        if (normalized.isBlank()) {
            return LookupResult.failed(query, "", "invalid_query");
        }

        if (configManager.isIpIntelligenceSkipPrivateIp() && isPrivateOrLocalAddress(normalized)) {
            return LookupResult.skippedPrivate(normalized);
        }

        CacheEntry cached = cache.get(normalized);
        if (cached != null && !cached.isExpired()) {
            return cached.result();
        }

        LookupResult fromIpApi = lookupIpApi(normalized);
        LookupResult fromIpInfo = lookupIpInfo(normalized);
        LookupResult merged = merge(fromIpApi, fromIpInfo, normalized, query);
        cache.put(normalized, new CacheEntry(merged, Instant.now().plus(Duration.ofMinutes(configManager.getIpIntelligenceCacheMinutes()))));
        return merged;
    }

    public boolean isPrivateOrLocalAddress(String rawIp) {
        try {
            InetAddress address = InetAddress.getByName(rawIp);
            return address.isAnyLocalAddress()
                    || address.isLinkLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress();
        } catch (Exception exception) {
            return false;
        }
    }

    public void clearCache() {
        cache.clear();
    }

    private LookupResult lookupIpApi(String ip) {
        String endpoint = IP_API_BASE + urlEncode(ip)
                + "?fields=status,message,query,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting";
        HttpResponse<String> response = sendGet(endpoint);
        if (response == null) {
            return LookupResult.failed(ip, ip, "ip_api_request_failed");
        }

        if (response.statusCode() != 200) {
            return LookupResult.failed(ip, ip, "ip_api_http_" + response.statusCode());
        }

        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            String status = stringValue(json, "status");
            if (!"success".equalsIgnoreCase(status)) {
                String message = stringValue(json, "message");
                return LookupResult.failed(ip, stringValueOr(json, "query", ip),
                        message.isBlank() ? "ip_api_not_success" : "ip_api_" + sanitizeReason(message));
            }

            return new LookupResult(
                    true,
                    ip,
                    stringValueOr(json, "query", ip),
                    stringValue(json, "country"),
                    stringValue(json, "countryCode"),
                    stringValue(json, "regionName"),
                    stringValue(json, "city"),
                    stringValue(json, "isp"),
                    stringValue(json, "org"),
                    stringValue(json, "as"),
                    boolValue(json, "proxy"),
                    boolValue(json, "hosting"),
                    boolValue(json, "mobile"),
                    "ip-api",
                    "ok",
                    false
            );
        } catch (Exception exception) {
            return LookupResult.failed(ip, ip, "ip_api_parse_error");
        }
    }

    private LookupResult lookupIpInfo(String ip) {
        String token = configManager.getIpInfoToken();
        if (token.isBlank()) {
            return LookupResult.failed(ip, ip, "ipinfo_token_missing");
        }

        String endpoint = IPINFO_BASE + urlEncode(ip) + "?token=" + urlEncode(token);
        HttpResponse<String> response = sendGet(endpoint);
        if (response == null) {
            return LookupResult.failed(ip, ip, "ipinfo_request_failed");
        }
        if (response.statusCode() != 200) {
            return LookupResult.failed(ip, ip, "ipinfo_http_" + response.statusCode());
        }

        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (json.has("error")) {
                return LookupResult.failed(ip, ip, "ipinfo_error");
            }

            String ipValue = firstNonBlank(stringValue(json, "ip"), stringValue(json, "query"), ip);
            String country = firstNonBlank(stringValue(json, "country"), stringValue(json, "country_name"));
            String countryCode = firstNonBlank(stringValue(json, "country_code"), stringValue(json, "country"));
            String region = firstNonBlank(stringValue(json, "region"), stringValue(json, "region_name"));
            String city = stringValue(json, "city");
            String asn = firstNonBlank(stringValue(json, "asn"), stringValue(json, "as_number"));
            String organization = firstNonBlank(stringValue(json, "as_name"), stringValue(json, "as_domain"), stringValue(json, "org"));
            boolean mobile = boolValue(json, "is_mobile") || boolValue(json, "mobile");
            boolean proxy = boolValue(json, "is_anonymous") || boolValue(json, "anonymous") || boolValue(json, "proxy");
            boolean hosting = boolValue(json, "is_hosting") || boolValue(json, "hosting");

            return new LookupResult(
                    true,
                    ip,
                    ipValue,
                    country,
                    countryCode,
                    region,
                    city,
                    "",
                    organization,
                    asn,
                    proxy,
                    hosting,
                    mobile,
                    "ipinfo-lite",
                    "ok",
                    false
            );
        } catch (Exception exception) {
            return LookupResult.failed(ip, ip, "ipinfo_parse_error");
        }
    }

    private LookupResult merge(LookupResult ipApi, LookupResult ipInfo, String resolvedIp, String requestedQuery) {
        if (!ipApi.success() && !ipInfo.success()) {
            return LookupResult.failed(requestedQuery, resolvedIp,
                    "all_sources_failed:" + ipApi.note() + "+" + ipInfo.note());
        }

        LookupResult primary = ipApi.success() ? ipApi : ipInfo;
        LookupResult secondary = ipApi.success() ? ipInfo : ipApi;
        boolean bothSuccess = ipApi.success() && ipInfo.success();
        String source = bothSuccess ? "ip-api+ipinfo-lite" : primary.source();
        String note = bothSuccess ? "ok_merged" : primary.note();

        return new LookupResult(
                true,
                requestedQuery,
                firstNonBlank(primary.resolvedIp(), secondary.resolvedIp(), resolvedIp),
                firstNonBlank(primary.country(), secondary.country()),
                firstNonBlank(primary.countryCode(), secondary.countryCode()),
                firstNonBlank(primary.region(), secondary.region()),
                firstNonBlank(primary.city(), secondary.city()),
                firstNonBlank(primary.isp(), secondary.isp()),
                firstNonBlank(primary.organization(), secondary.organization()),
                firstNonBlank(primary.asn(), secondary.asn()),
                primary.proxy() || secondary.proxy(),
                primary.hosting() || secondary.hosting(),
                primary.mobile() || secondary.mobile(),
                source,
                note,
                primary.skippedPrivate() || secondary.skippedPrivate()
        );
    }

    private HttpResponse<String> sendGet(String endpoint) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint))
                .GET()
                .timeout(Duration.ofMillis(configManager.getIpIntelligenceRequestTimeoutMillis()))
                .header("Accept", "application/json")
                .header("User-Agent", "AuthManager-IP/1.0")
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

    private String normalizeQuery(String query) {
        if (query == null) {
            return "";
        }
        String normalized = query.trim();
        if (normalized.isBlank()) {
            return "";
        }
        if (normalized.contains(":") && normalized.indexOf(':') == normalized.lastIndexOf(':')) {
            String[] split = normalized.split(":", 2);
            if (split.length == 2 && split[1].chars().allMatch(Character::isDigit)) {
                normalized = split[0];
            }
        }
        return normalized;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String stringValue(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).isJsonNull()) {
            return "";
        }
        try {
            return json.get(key).getAsString().trim();
        } catch (Exception exception) {
            return "";
        }
    }

    private String stringValueOr(JsonObject json, String key, String defaultValue) {
        String value = stringValue(json, key);
        return value.isBlank() ? defaultValue : value;
    }

    private boolean boolValue(JsonObject json, String key) {
        if (!json.has(key) || json.get(key).isJsonNull()) {
            return false;
        }
        try {
            if (json.get(key).isJsonPrimitive() && json.get(key).getAsJsonPrimitive().isBoolean()) {
                return json.get(key).getAsBoolean();
            }
            String string = json.get(key).getAsString().trim().toLowerCase(Locale.ROOT);
            return "true".equals(string) || "1".equals(string) || "yes".equals(string);
        } catch (Exception exception) {
            return false;
        }
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private String sanitizeReason(String input) {
        if (input == null || input.isBlank()) {
            return "unknown";
        }
        return input.toLowerCase(Locale.ROOT).replace(' ', '_');
    }

    public record LookupResult(
            boolean success,
            String requestedQuery,
            String resolvedIp,
            String country,
            String countryCode,
            String region,
            String city,
            String isp,
            String organization,
            String asn,
            boolean proxy,
            boolean hosting,
            boolean mobile,
            String source,
            String note,
            boolean skippedPrivate
    ) {
        public static LookupResult failed(String requestedQuery, String resolvedIp, String note) {
            return new LookupResult(false, requestedQuery, resolvedIp, "", "", "", "", "", "",
                    "", false, false, false, "none", note, false);
        }

        public static LookupResult skippedPrivate(String ip) {
            return new LookupResult(true, ip, ip, "", "", "", "", "", "", "",
                    false, false, false, "private-ip", "skipped_private_ip", true);
        }

        public boolean suspicious() {
            return proxy || hosting;
        }
    }

    private record CacheEntry(LookupResult result, Instant expiresAt) {
        private boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
