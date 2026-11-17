package dev.keyvault.webhook;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.Codec;
import dev.keyvault.common.Rows;
import dev.keyvault.common.ServerCrypto;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Outgoing webhooks via a transactional outbox:
 *  1. enqueue() inserts delivery rows in the SAME transaction as the change, so an event is
 *     emitted if and only if the change committed;
 *  2. a dispatcher leases due rows with FOR UPDATE SKIP LOCKED (safe with several instances),
 *     sends them outside any transaction, and records the outcome with exponential backoff.
 * Requests are signed Stripe-style: X-KeyVault-Signature: t=&lt;unix&gt;,v1=hex(HMAC-SHA256(secret, t.body)).
 * Payloads never contain secret names or values; KeyVault couldn't include them if it wanted to.
 */
@Service
public class WebhookService {
    private static final Logger log = LoggerFactory.getLogger(WebhookService.class);
    public static final List<String> EVENTS = List.of(
            "secret.created", "secret.updated", "secret.deleted", "secret.rolled_back",
            "environment.key_rotated", "change_request.opened", "change_request.applied", "change_request.rejected");
    private static final int MAX_ATTEMPTS = 8;
    private static final String AAD = "webhook-secret";

    private final JdbcClient db;
    private final ServerCrypto crypto;
    private final TransactionTemplate tx;
    private final boolean allowHttp;
    private final boolean allowPrivate;
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER) // a redirect could point at an internal address
            .build();

    public WebhookService(JdbcClient db, ServerCrypto crypto, PlatformTransactionManager txm,
                          @Value("${keyvault.webhooks.allow-http:false}") boolean allowHttp,
                          @Value("${keyvault.webhooks.allow-private-networks:false}") boolean allowPrivate) {
        this.db = db;
        this.crypto = crypto;
        this.tx = new TransactionTemplate(txm);
        this.allowHttp = allowHttp;
        this.allowPrivate = allowPrivate;
    }

    // ------------------------------------------------------------- management

    public record WebhookView(UUID id, UUID environmentId, String url, List<String> events, boolean enabled,
                              Instant createdAt, int consecutiveFailures, String lastStatus, Instant lastDeliveryAt) {}

    public record Created(WebhookView webhook, String signingSecret) {}

    public record DeliveryView(UUID id, String event, String status, int attempts, Integer responseCode, String lastError,
                               Instant createdAt, Instant deliveredAt, Instant nextAttemptAt) {}

    public List<WebhookView> list(UUID projectId) {
        return db.sql("""
                SELECT w.*, d.status AS last_status, d.created_at AS last_at FROM webhooks w
                LEFT JOIN LATERAL (SELECT status, created_at FROM webhook_deliveries WHERE webhook_id = w.id ORDER BY created_at DESC LIMIT 1) d ON TRUE
                WHERE w.project_id = ? ORDER BY w.created_at
                """)
                .param(projectId)
                .query((rs, i) -> new WebhookView(Rows.uuid(rs, "id"), Rows.uuid(rs, "environment_id"), rs.getString("url"),
                        List.of(rs.getString("events").split(",")), rs.getBoolean("enabled"), Rows.instant(rs, "created_at"),
                        rs.getInt("consecutive_failures"), rs.getString("last_status"), Rows.instant(rs, "last_at")))
                .list();
    }

    public Created create(UUID projectId, UUID environmentId, String url, List<String> events, UUID createdBy) {
        validateUrl(url, true);
        for (String e : events) {
            if (!e.equals("*") && !EVENTS.contains(e)) throw ApiException.badRequest("Unknown event: " + e);
        }
        if (events.isEmpty()) throw ApiException.badRequest("Choose at least one event");
        int count = db.sql("SELECT COUNT(*) FROM webhooks WHERE project_id = ?").param(projectId).query(Integer.class).single();
        if (count >= 10) throw ApiException.badRequest("A project can have at most 10 webhooks");
        String secret = "whsec_" + Codec.randomToken(32);
        UUID id = UUID.randomUUID();
        db.sql("INSERT INTO webhooks (id, project_id, environment_id, url, secret_enc, events, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)")
                .params(id, projectId, environmentId, url.trim(), crypto.encrypt(secret.getBytes(StandardCharsets.UTF_8), AAD + ":" + id),
                        String.join(",", events), createdBy, Rows.now())
                .update();
        WebhookView view = list(projectId).stream().filter(w -> w.id().equals(id)).findFirst().orElseThrow();
        return new Created(view, secret);
    }

    public void setEnabled(UUID projectId, UUID id, boolean enabled) {
        int n = db.sql("UPDATE webhooks SET enabled = ?, consecutive_failures = 0 WHERE id = ? AND project_id = ?")
                .params(enabled, id, projectId).update();
        if (n == 0) throw ApiException.notFound("Webhook");
    }

    public void delete(UUID projectId, UUID id) {
        int n = db.sql("DELETE FROM webhooks WHERE id = ? AND project_id = ?").params(id, projectId).update();
        if (n == 0) throw ApiException.notFound("Webhook");
    }

    public List<DeliveryView> deliveries(UUID projectId, UUID webhookId) {
        return db.sql("""
                SELECT d.* FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
                WHERE d.webhook_id = ? AND w.project_id = ? ORDER BY d.created_at DESC LIMIT 50
                """)
                .params(webhookId, projectId)
                .query((rs, i) -> new DeliveryView(Rows.uuid(rs, "id"), rs.getString("event"), rs.getString("status"),
                        rs.getInt("attempts"), (Integer) rs.getObject("response_code"), rs.getString("last_error"),
                        Rows.instant(rs, "created_at"), Rows.instant(rs, "delivered_at"), Rows.instant(rs, "next_attempt_at")))
                .list();
    }

    /** Queue a "ping" for one webhook and deliver it right away so the UI can show the result. */
    public DeliveryView ping(UUID projectId, UUID webhookId) {
        boolean exists = db.sql("SELECT EXISTS(SELECT 1 FROM webhooks WHERE id = ? AND project_id = ?)")
                .params(webhookId, projectId).query(Boolean.class).single();
        if (!exists) throw ApiException.notFound("Webhook");
        // inserted already leased, so the background dispatcher can't send it a second time
        UUID deliveryId = insertDelivery(webhookId, "ping", Map.of("projectId", projectId.toString(), "message", "Hello from KeyVault"),
                Instant.now().plusSeconds(120));
        deliver(deliveryId);
        return deliveries(projectId, webhookId).stream().filter(d -> d.id().equals(deliveryId)).findFirst().orElseThrow();
    }

    public void redeliver(UUID projectId, UUID deliveryId) {
        int n = db.sql("""
                UPDATE webhook_deliveries SET status = 'PENDING', next_attempt_at = ?, attempts = 0
                WHERE id = ? AND webhook_id IN (SELECT id FROM webhooks WHERE project_id = ?)
                """).params(Rows.now(), deliveryId, projectId).update();
        if (n == 0) throw ApiException.notFound("Delivery");
    }

    // ----------------------------------------------------------------- outbox

    /** Must be called inside the transaction that performs the change. */
    public void enqueue(UUID projectId, UUID environmentId, String event, Map<String, ?> data) {
        List<UUID> targets = db.sql("""
                SELECT id FROM webhooks WHERE project_id = ? AND enabled
                  AND (environment_id IS NULL OR environment_id = ?)
                  AND (events = '*' OR (',' || events || ',') LIKE ?)
                """)
                .params(projectId, environmentId, "%," + event + ",%")
                .query(UUID.class).list();
        for (UUID w : targets) {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("projectId", projectId.toString());
            if (environmentId != null) payload.put("environmentId", environmentId.toString());
            payload.put("data", data);
            insertDelivery(w, event, payload, Instant.now());
        }
    }

    private UUID insertDelivery(UUID webhookId, String event, Map<String, ?> data, Instant firstAttempt) {
        UUID id = UUID.randomUUID();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id.toString());
        body.put("event", event);
        body.put("createdAt", Instant.now().toString());
        body.putAll(data);
        db.sql("INSERT INTO webhook_deliveries (id, webhook_id, event, payload, status, next_attempt_at, created_at) VALUES (?,?,?,?, 'PENDING', ?, ?)")
                .params(id, webhookId, event, toJson(body), Rows.ts(firstAttempt), Rows.now())
                .update();
        return id;
    }

    @Scheduled(fixedDelayString = "${keyvault.webhooks.poll-interval:PT2S}", initialDelayString = "PT5S")
    public void dispatchDue() {
        // Lease up to 25 due deliveries; SKIP LOCKED lets several instances share the queue safely.
        List<UUID> leased = tx.execute(status -> {
            List<UUID> ids = db.sql("""
                    SELECT id FROM webhook_deliveries WHERE status = 'PENDING' AND next_attempt_at <= ?
                    ORDER BY next_attempt_at LIMIT 25 FOR UPDATE SKIP LOCKED
                    """).param(Rows.now()).query(UUID.class).list();
            for (UUID id : ids) {
                db.sql("UPDATE webhook_deliveries SET next_attempt_at = ? WHERE id = ?")
                        .params(Rows.ts(Instant.now().plusSeconds(120)), id).update();
            }
            return ids;
        });
        if (leased != null) leased.forEach(this::deliver);
    }

    void deliver(UUID deliveryId) {
        record Row(UUID webhookId, String url, String secretEnc, String event, String payload, int attempts, boolean enabled) {}
        Row r = db.sql("""
                SELECT d.webhook_id, w.url, w.secret_enc, d.event, d.payload, d.attempts, w.enabled
                FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE d.id = ?
                """).param(deliveryId)
                .query((rs, i) -> new Row(Rows.uuid(rs, "webhook_id"), rs.getString("url"), rs.getString("secret_enc"),
                        rs.getString("event"), rs.getString("payload"), rs.getInt("attempts"), rs.getBoolean("enabled")))
                .optional().orElse(null);
        if (r == null) return;
        int attempt = r.attempts() + 1;
        Integer code = null;
        String error = null;
        try {
            validateUrl(r.url(), false); // re-check at send time: DNS may have changed since creation
            String secret = new String(crypto.decrypt(r.secretEnc(), AAD + ":" + r.webhookId()), StandardCharsets.UTF_8);
            long t = Instant.now().getEpochSecond();
            HttpRequest req = HttpRequest.newBuilder(URI.create(r.url()))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "KeyVault-Webhooks/2.1")
                    .header("X-KeyVault-Event", r.event())
                    .header("X-KeyVault-Delivery", deliveryId.toString())
                    .header("X-KeyVault-Signature", "t=" + t + ",v1=" + sign(secret, t, r.payload()))
                    .POST(HttpRequest.BodyPublishers.ofString(r.payload()))
                    .build();
            HttpResponse<Void> res = http.send(req, HttpResponse.BodyHandlers.discarding());
            code = res.statusCode();
            if (code < 200 || code >= 300) error = "Endpoint returned HTTP " + code;
        } catch (ApiException e) {
            error = e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            error = "Interrupted";
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        }
        boolean ok = error == null;
        String status = ok ? "SUCCEEDED" : attempt >= MAX_ATTEMPTS ? "FAILED" : "PENDING";
        // backoff: 30s, 1m, 2m, 4m … capped at 6h
        Instant next = Instant.now().plusSeconds(Math.min(30L << Math.min(attempt - 1, 10), 6 * 3600));
        db.sql("""
                UPDATE webhook_deliveries SET status = ?, attempts = ?, response_code = ?, last_error = ?, next_attempt_at = ?,
                  delivered_at = CASE WHEN ? THEN ? ELSE delivered_at END WHERE id = ?
                """)
                .params(status, attempt, code, error == null ? null : error.substring(0, Math.min(error.length(), 500)),
                        Rows.ts(next), ok, Rows.now(), deliveryId)
                .update();
        db.sql(ok ? "UPDATE webhooks SET consecutive_failures = 0 WHERE id = ?"
                        : "UPDATE webhooks SET consecutive_failures = consecutive_failures + 1, enabled = (consecutive_failures + 1 < 20) WHERE id = ?")
                .param(r.webhookId()).update();
        if (!ok) log.info("Webhook delivery {} attempt {} failed: {}", deliveryId, attempt, error);
    }

    // ------------------------------------------------------------- security

    static String sign(String secret, long timestamp, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Codec.hex(mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * SSRF guard: only http(s), https unless explicitly allowed, no credentials in the URL, and every
     * resolved address must be public (no loopback, private, link-local/cloud-metadata, or multicast).
     */
    public void validateUrl(String url, boolean atCreation) {
        URI u;
        try {
            u = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("Invalid URL");
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        if (!scheme.equals("https") && !(scheme.equals("http") && allowHttp)) throw ApiException.badRequest("Webhook URLs must use https://");
        if (u.getHost() == null || u.getRawUserInfo() != null) throw ApiException.badRequest("Invalid webhook host");
        if (url.length() > 2048) throw ApiException.badRequest("URL too long");
        if (allowPrivate) return;
        InetAddress[] addrs;
        try {
            addrs = InetAddress.getAllByName(u.getHost());
        } catch (UnknownHostException e) {
            if (atCreation) throw ApiException.badRequest("Could not resolve " + u.getHost());
            throw new ApiException(org.springframework.http.HttpStatus.BAD_GATEWAY, "dns", "Could not resolve host");
        }
        for (InetAddress a : addrs) {
            if (isInternal(a)) throw ApiException.badRequest("Webhook URLs must point to a public address");
        }
    }

    static boolean isInternal(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress() || a.isMulticastAddress()) return true;
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            int x = b[0] & 0xff, y = b[1] & 0xff;
            return x == 0 || x == 10 || (x == 100 && y >= 64 && y <= 127) || (x == 169 && y == 254) || (x == 172 && y >= 16 && y <= 31)
                    || (x == 192 && y == 168) || (x == 198 && (y == 18 || y == 19)) || x >= 224;
        }
        if (a instanceof Inet6Address) return (b[0] & 0xfe) == 0xfc; // fc00::/7 unique-local
        return false;
    }

    private String toJson(Object o) {
        try {
            return json.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
