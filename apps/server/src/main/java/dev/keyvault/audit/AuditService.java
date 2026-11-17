package dev.keyvault.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.Codec;
import dev.keyvault.common.Rows;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import jakarta.annotation.PreDestroy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Append-only, hash-chained audit log. Each chain ("project:&lt;id&gt;" or "user:&lt;id&gt;") is a
 * linked list where hash_n = SHA-256(hash_{n-1} || canonical(event_n)). Editing, deleting or
 * reordering any event breaks every later hash, which {@link #verify(String)} detects.
 * The chain head row is locked (SELECT … FOR UPDATE) so concurrent writers serialise per chain.
 */
@Service
public class AuditService {
    public static final String GENESIS = "0".repeat(64);
    private static final ObjectMapper CANONICAL = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private final JdbcClient db;
    private final TransactionTemplate tx;

    public AuditService(JdbcClient db, PlatformTransactionManager txManager) {
        this.db = db;
        this.tx = new TransactionTemplate(txManager);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public enum ActorType { USER, SERVICE_TOKEN, ANONYMOUS, SYSTEM }

    public record Actor(ActorType type, UUID id, String label) {
        public static Actor user(UUID id, String email) { return new Actor(ActorType.USER, id, email); }
        public static Actor token(UUID id, String name) { return new Actor(ActorType.SERVICE_TOKEN, id, "token:" + name); }
        public static Actor anonymous() { return new Actor(ActorType.ANONYMOUS, null, "anonymous"); }
    }

    public record Event(Actor actor, UUID projectId, String action, String targetType, String targetId, Map<String, ?> details) {
        public static Event of(Actor actor, UUID projectId, String action) {
            return new Event(actor, projectId, action, null, null, Map.of());
        }
        public Event target(String type, Object id) { return new Event(actor, projectId, action, type, Objects.toString(id, null), details); }
        public Event details(Map<String, ?> d) { return new Event(actor, projectId, action, targetType, targetId, d); }
    }

    public record EventView(long seq, long chainIndex, Instant occurredAt, String actorType, UUID actorId, String actorLabel,
                            UUID projectId, String action, String targetType, String targetId, String ip, String userAgent,
                            Map<String, Object> details, String hash) {}

    public record VerifyResult(boolean valid, long eventsChecked, Long firstBrokenIndex, String headHash) {}

    public static String chainFor(UUID projectId, UUID actorId) {
        if (projectId != null) return "project:" + projectId;
        return "user:" + (actorId == null ? "anonymous" : actorId);
    }

    @Transactional
    public void record(Event e) {
        record(e, chainFor(e.projectId(), e.actor().id()));
    }

    @Transactional
    public void record(Event e, String chainKey) {
        append(chainKey, List.of(new Pending(e, chainKey, ClientInfo.current(), Instant.now().truncatedTo(ChronoUnit.MICROS))));
    }

    // ------------------------------------------------------------ buffered reads
    //
    // Reads are by far the most frequent event. Appending each one synchronously would hold the
    // chain-head row lock (and a commit) per request, serialising every read in a project. Instead
    // reads are buffered and appended in batches: one lock and one commit per chain per flush.
    // Mutations still use record(): they commit atomically with the change they describe.

    public record Pending(Event event, String chainKey, ClientInfo client, Instant at) {}

    private final LinkedBlockingQueue<Pending> buffer = new LinkedBlockingQueue<>(50_000);

    public void recordAsync(Event e) {
        String chainKey = chainFor(e.projectId(), e.actor().id());
        Pending p = new Pending(e, chainKey, ClientInfo.current(), Instant.now().truncatedTo(ChronoUnit.MICROS));
        if (!buffer.offer(p)) record(e, chainKey); // backpressure: never drop an audit event
    }

    @Scheduled(fixedDelayString = "PT0.25S")
    public void scheduledFlush() {
        flushNow();
    }

    @PreDestroy
    public void shutdownFlush() {
        flushNow();
    }

    /** Drains the buffer; called before anything reads the log so readers always see a complete chain. */
    public synchronized void flushNow() {
        List<Pending> batch = new ArrayList<>();
        buffer.drainTo(batch);
        if (batch.isEmpty()) return;
        Map<String, List<Pending>> byChain = new LinkedHashMap<>();
        for (Pending p : batch) byChain.computeIfAbsent(p.chainKey(), k -> new ArrayList<>()).add(p);
        byChain.forEach((chain, events) -> tx.executeWithoutResult(status -> append(chain, events)));
    }

    /** Appends events to one chain under a single head lock. */
    private void append(String chainKey, List<Pending> events) {
        db.sql("INSERT INTO audit_chain_heads (chain_key, last_index, last_hash) VALUES (?, 0, ?) ON CONFLICT DO NOTHING")
                .params(chainKey, GENESIS).update();
        record Head(long index, String hash) {}
        Head head = db.sql("SELECT last_index, last_hash FROM audit_chain_heads WHERE chain_key = ? FOR UPDATE")
                .param(chainKey).query((rs, i) -> new Head(rs.getLong(1), rs.getString(2))).single();
        long index = head.index();
        String prev = head.hash();
        for (Pending p : events) {
            Event e = p.event();
            index++;
            String details = canonicalJson(e.details());
            String hash = hash(prev, chainKey, index, p.at(), e.actor().type().name(), e.actor().id(), e.actor().label(),
                    e.projectId(), e.action(), e.targetType(), e.targetId(), p.client().ip(), details);
            db.sql("""
                    INSERT INTO audit_events (chain_key, chain_index, occurred_at, actor_type, actor_id, actor_label, project_id,
                      action, target_type, target_id, ip, user_agent, details, prev_hash, hash)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """)
                    .params(chainKey, index, Rows.ts(p.at()), e.actor().type().name(), e.actor().id(), e.actor().label(),
                            e.projectId(), e.action(), e.targetType(), e.targetId(), p.client().ip(), p.client().userAgent(),
                            details, prev, hash)
                    .update();
            prev = hash;
        }
        db.sql("UPDATE audit_chain_heads SET last_index = ?, last_hash = ? WHERE chain_key = ?")
                .params(index, prev, chainKey).update();
    }

    public List<EventView> list(String chainKey, Long beforeSeq, int limit) {
        flushNow();
        return db.sql("""
                SELECT * FROM audit_events WHERE chain_key = ? AND seq < ? ORDER BY seq DESC LIMIT ?
                """)
                .params(chainKey, beforeSeq == null ? Long.MAX_VALUE : beforeSeq, Math.min(Math.max(limit, 1), 200))
                .query((rs, i) -> new EventView(rs.getLong("seq"), rs.getLong("chain_index"), Rows.instant(rs, "occurred_at"),
                        rs.getString("actor_type"), Rows.uuid(rs, "actor_id"), rs.getString("actor_label"),
                        Rows.uuid(rs, "project_id"), rs.getString("action"), rs.getString("target_type"),
                        rs.getString("target_id"), rs.getString("ip"), rs.getString("user_agent"),
                        parse(rs.getString("details")), rs.getString("hash")))
                .list();
    }

    /** Recomputes the full chain. O(n) streaming; nothing is loaded into memory at once. */
    public VerifyResult verify(String chainKey) {
        flushNow();
        AtomicReference<String> prev = new AtomicReference<>(GENESIS);
        long[] expectedIndex = {1};
        Long[] broken = {null};
        db.sql("SELECT * FROM audit_events WHERE chain_key = ? ORDER BY chain_index").param(chainKey).query(rs -> {
            if (broken[0] != null) return;
            long index = rs.getLong("chain_index");
            String computed = hash(prev.get(), chainKey, index, Rows.instant(rs, "occurred_at"), rs.getString("actor_type"),
                    Rows.uuid(rs, "actor_id"), rs.getString("actor_label"), Rows.uuid(rs, "project_id"), rs.getString("action"),
                    rs.getString("target_type"), rs.getString("target_id"), rs.getString("ip"), rs.getString("details"));
            if (index != expectedIndex[0] || !prev.get().equals(rs.getString("prev_hash")) || !computed.equals(rs.getString("hash"))) {
                broken[0] = index;
                return;
            }
            prev.set(computed);
            expectedIndex[0]++;
        });
        String head = db.sql("SELECT last_hash FROM audit_chain_heads WHERE chain_key = ?").param(chainKey)
                .query(String.class).optional().orElse(GENESIS);
        long checked = expectedIndex[0] - 1;
        if (broken[0] == null && !head.equals(prev.get())) broken[0] = checked + 1; // tail truncated
        return new VerifyResult(broken[0] == null, checked, broken[0], head);
    }

    static String hash(String prev, String chainKey, long index, Instant at, String actorType, UUID actorId, String actorLabel,
                       UUID projectId, String action, String targetType, String targetId, String ip, String details) {
        // Length-prefixed fields: unambiguous even if a field contains the separator.
        StringBuilder sb = new StringBuilder();
        for (Object f : new Object[]{prev, chainKey, index, at.truncatedTo(ChronoUnit.MICROS).toString(), actorType, actorId,
                actorLabel, projectId, action, targetType, targetId, ip, details}) {
            String s = f == null ? "" : f.toString();
            sb.append(s.length()).append(':').append(s).append('|');
        }
        return Codec.sha256Hex(sb.toString());
    }

    private static String canonicalJson(Map<String, ?> details) {
        try {
            return CANONICAL.writeValueAsString(details == null ? Map.of() : new TreeMap<>(details));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Map<String, Object> parse(String json) {
        try {
            return CANONICAL.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException ex) {
            return Map.of();
        }
    }
}
