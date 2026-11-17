package dev.keyvault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.keyvault.auth.TotpService;
import dev.keyvault.common.Codec;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import jakarta.servlet.http.Cookie;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * End-to-end API tests against a real (embedded) PostgreSQL. Crypto material is random but
 * well-formed: the server must never need to understand it, which is the point.
 */
@SpringBootTest
@AutoConfigureMockMvc
@org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@ActiveProfiles("test")
class ApiIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcClient db;

    static String key32() { return Codec.randomToken(32); }
    static String env() { return "kv1." + Codec.randomToken(48); }
    static String sealed() { return "kv1s." + Codec.randomToken(88); }
    static String uuid() { return UUID.randomUUID().toString(); }

    record Account(String email, String authKey, Cookie cookie, String userId) {}

    Account register(String name) throws Exception {
        String email = name + "-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        String authKey = key32();
        Map<String, Object> body = new HashMap<>();
        body.put("email", email);
        body.put("displayName", name);
        body.put("kdf", Map.of("algorithm", "argon2id", "memoryKiB", 65536, "iterations", 3, "parallelism", 1));
        body.put("salt", Codec.randomToken(16));
        body.put("authKey", authKey);
        body.put("protectedAccountKey", env());
        body.put("publicKey", key32());
        body.put("protectedPrivateKey", env());
        body.put("recoveryVerifier", key32());
        body.put("recoveryProtectedAccountKey", env());
        MvcResult r = mvc.perform(api(post("/api/auth/register"), null, body)).andExpect(status().isOk()).andReturn();
        Cookie c = r.getResponse().getCookie("__Host-kv_session");
        assertThat(c).isNotNull();
        assertThat(c.isHttpOnly()).isTrue();
        assertThat(c.getSecure()).isTrue();
        String setCookie = r.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).contains("SameSite=Strict");
        JsonNode res = json.readTree(r.getResponse().getContentAsString());
        return new Account(email, authKey, c, res.at("/session/user/id").asText());
    }

    MockHttpServletRequestBuilder api(MockHttpServletRequestBuilder b, Account a, Object body) throws Exception {
        b.header("X-KV-Request", "1").contentType(MediaType.APPLICATION_JSON);
        if (a != null) b.cookie(a.cookie());
        if (body != null) b.content(json.writeValueAsString(body));
        return b;
    }

    JsonNode call(MockHttpServletRequestBuilder b, Account a, Object body, int expected) throws Exception {
        String s = mvc.perform(api(b, a, body)).andExpect(status().is(expected)).andReturn().getResponse().getContentAsString();
        return s.isEmpty() ? null : json.readTree(s);
    }

    record Project(String id, List<String> envIds) {}

    Project createProject(Account a) throws Exception {
        String pid = uuid();
        List<Map<String, String>> envs = new ArrayList<>();
        List<String> ids = new ArrayList<>();
        for (String slug : List.of("development", "production")) {
            String id = uuid();
            ids.add(id);
            envs.add(Map.of("id", id, "name", slug, "slug", slug, "wrappedKey", sealed()));
        }
        JsonNode p = call(post("/api/projects"), a, Map.of("id", pid, "name", "Payments", "description", "", "environments", envs), 200);
        assertThat(p.get("role").asText()).isEqualTo("OWNER");
        assertThat(p.get("environments")).hasSize(2);
        return new Project(pid, ids);
    }

    Map<String, Object> secret(String id) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", id);
        m.put("nameIndex", key32());
        m.put("nameCiphertext", env());
        m.put("valueCiphertext", env());
        m.put("commentCiphertext", null);
        m.put("keyVersion", 1);
        return m;
    }

    // ------------------------------------------------------------------ auth

    @Test
    void registerLoginAndSession() throws Exception {
        Account a = register("alice");
        call(get("/api/auth/session"), a, null, 200);

        // wrong credential
        call(post("/api/auth/login"), null, Map.of("email", a.email(), "authKey", key32()), 401);
        // right credential
        JsonNode ok = call(post("/api/auth/login"), null, Map.of("email", a.email(), "authKey", a.authKey()), 200);
        assertThat(ok.get("mfaRequired").asBoolean()).isFalse();
        assertThat(ok.at("/session/protectedAccountKey").asText()).startsWith("kv1.");
        // the server must not store the auth key itself
        String stored = db.sql("SELECT auth_hash FROM users WHERE email = ?").param(a.email()).query(String.class).single();
        assertThat(stored).startsWith("$argon2id$").doesNotContain(a.authKey());
    }

    @Test
    void preloginDoesNotRevealWhetherAccountExists() throws Exception {
        JsonNode a = call(post("/api/auth/prelogin"), null, Map.of("email", "ghost@example.com"), 200);
        JsonNode b = call(post("/api/auth/prelogin"), null, Map.of("email", "ghost@example.com"), 200);
        assertThat(a.get("salt").asText()).isEqualTo(b.get("salt").asText()).hasSize(22);
        assertThat(a.at("/kdf/algorithm").asText()).isEqualTo("argon2id");
    }

    @Test
    void rejectsWeakKdfParameters() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("email", "weak@example.com");
        body.put("displayName", "w");
        body.put("kdf", Map.of("algorithm", "argon2id", "memoryKiB", 1024, "iterations", 1, "parallelism", 1));
        body.put("salt", Codec.randomToken(16));
        body.put("authKey", key32());
        body.put("protectedAccountKey", env());
        body.put("publicKey", key32());
        body.put("protectedPrivateKey", env());
        body.put("recoveryVerifier", key32());
        body.put("recoveryProtectedAccountKey", env());
        call(post("/api/auth/register"), null, body, 400);
    }

    @Test
    void csrfGuardRejectsCrossSiteWrites() throws Exception {
        Account a = register("csrf");
        // no custom header → rejected
        mvc.perform(post("/api/sends").cookie(a.cookie()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        // foreign Origin → rejected
        mvc.perform(api(post("/api/account/sessions/revoke-others"), a, null).header("Origin", "https://evil.example"))
                .andExpect(status().isForbidden());
        // same origin → accepted
        mvc.perform(api(post("/api/account/sessions/revoke-others"), a, null).header("Origin", "http://localhost:8080"))
                .andExpect(status().isOk());
    }

    @Test
    void securityHeadersArePresent() throws Exception {
        mvc.perform(get("/api/config"))
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("frame-ancestors 'none'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    void logoutRevokesSession() throws Exception {
        Account a = register("logout");
        call(post("/api/auth/logout"), a, null, 204);
        call(get("/api/auth/session"), a, null, 401);
    }

    @Test
    void totpFlowWithReplayProtection() throws Exception {
        Account a = register("totp");
        JsonNode setup = call(post("/api/account/totp/setup"), a, Map.of("currentAuthKey", a.authKey()), 200);
        byte[] seed = TotpService.fromBase32(setup.get("secret").asText());
        long step = System.currentTimeMillis() / 1000 / 30;
        String code = TotpService.generate(seed, step);
        JsonNode enabled = call(post("/api/account/totp/enable"), a, Map.of("code", code), 200);
        assertThat(enabled.get("recoveryCodes")).hasSize(10);

        JsonNode login = call(post("/api/auth/login"), null, Map.of("email", a.email(), "authKey", a.authKey()), 200);
        assertThat(login.get("mfaRequired").asBoolean()).isTrue();
        assertThat(login.get("session").isNull()).isTrue();
        String mfa = login.get("mfaToken").asText();
        // replaying the code used during enrolment must fail
        call(post("/api/auth/login/mfa"), null, Map.of("mfaToken", mfa, "code", code), 401);
        // a one-time recovery code works exactly once
        String rc = enabled.get("recoveryCodes").get(0).asText();
        call(post("/api/auth/login/mfa"), null, Map.of("mfaToken", mfa, "code", rc), 200);
        JsonNode login2 = call(post("/api/auth/login"), null, Map.of("email", a.email(), "authKey", a.authKey()), 200);
        call(post("/api/auth/login/mfa"), null, Map.of("mfaToken", login2.get("mfaToken").asText(), "code", rc), 401);
    }

    // ------------------------------------------------------------- projects

    @Test
    void outsidersCannotSeeProjectsAndViewersCannotWrite() throws Exception {
        Account owner = register("owner");
        Account viewer = register("viewer");
        Account outsider = register("outsider");
        Project p = createProject(owner);

        call(get("/api/projects/" + p.id()), outsider, null, 404);
        call(get("/api/environments/" + p.envIds().get(0) + "/secrets"), outsider, null, 404);

        call(post("/api/projects/" + p.id() + "/members"), owner, Map.of("userId", viewer.userId(), "role", "VIEWER",
                "grants", List.of(Map.of("environmentId", p.envIds().get(0), "wrappedKey", sealed()))), 200);

        call(get("/api/environments/" + p.envIds().get(0) + "/secrets"), viewer, null, 200);
        // no grant for production → cannot read it even though they are a member
        call(get("/api/environments/" + p.envIds().get(1) + "/secrets"), viewer, null, 403);
        // viewer cannot write
        call(post("/api/environments/" + p.envIds().get(0) + "/secrets"), viewer, Map.of("secrets", List.of(secret(uuid()))), 403);
        // viewer cannot escalate
        call(patch("/api/projects/" + p.id() + "/members/" + viewer.userId()), viewer, Map.of("role", "OWNER"), 403);
    }

    @Test
    void removingMemberFlagsRotationAndLastOwnerIsProtected() throws Exception {
        Account owner = register("o");
        Account dev = register("d");
        Project p = createProject(owner);
        call(post("/api/projects/" + p.id() + "/members"), owner, Map.of("userId", dev.userId(), "role", "DEVELOPER",
                "grants", List.of(Map.of("environmentId", p.envIds().get(1), "wrappedKey", sealed()))), 200);
        call(delete("/api/projects/" + p.id() + "/members/" + dev.userId()), owner, null, 204);
        JsonNode detail = call(get("/api/projects/" + p.id()), owner, null, 200);
        assertThat(detail.at("/environments/1/rotationNeeded").asBoolean()).isTrue();
        assertThat(detail.at("/environments/0/rotationNeeded").asBoolean()).isFalse();
        call(delete("/api/projects/" + p.id() + "/members/" + owner.userId()), owner, null, 409);
    }

    // -------------------------------------------------------------- secrets

    @Test
    void secretLifecycleWithVersioningAndConflicts() throws Exception {
        Account a = register("dev");
        Project p = createProject(a);
        String env = p.envIds().get(0);
        String sid = uuid();
        Map<String, Object> s = secret(sid);
        call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(s)), 200);

        // duplicate name (same blind index) is rejected without the server knowing the name
        Map<String, Object> dup = secret(uuid());
        dup.put("nameIndex", s.get("nameIndex"));
        call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(dup)), 409);

        Map<String, Object> upd = new HashMap<>(s);
        upd.remove("id");
        upd.put("expectedVersion", 1);
        upd.put("valueCiphertext", env());
        JsonNode v2 = call(put("/api/environments/" + env + "/secrets/" + sid), a, upd, 200);
        assertThat(v2.get("version").asInt()).isEqualTo(2);
        // stale write (lost update) is rejected
        call(put("/api/environments/" + env + "/secrets/" + sid), a, upd, 409);

        call(post("/api/environments/" + env + "/secrets/" + sid + "/rollback"), a, Map.of("toVersion", 1, "expectedVersion", 2), 200);
        JsonNode versions = call(get("/api/environments/" + env + "/secrets/" + sid + "/versions"), a, null, 200);
        assertThat(versions).hasSize(3);
        assertThat(versions.get(0).get("changeType").asText()).isEqualTo("ROLLBACK");
        assertThat(versions.get(0).get("valueCiphertext").asText()).isEqualTo(s.get("valueCiphertext"));

        // stale key version rejected
        Map<String, Object> stale = secret(uuid());
        stale.put("keyVersion", 7);
        call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(stale)), 409);

        call(delete("/api/environments/" + env + "/secrets/" + sid), a, null, 204);
    }

    @Test
    void keyRotationReplacesEverythingAtomically() throws Exception {
        Account a = register("rot");
        Project p = createProject(a);
        String env = p.envIds().get(0);
        String sid = uuid();
        call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(secret(sid))), 200);
        String tokenId = Codec.randomToken(16);
        call(post("/api/environments/" + env + "/tokens"), a, Map.of("tokenId", tokenId, "name", "ci", "verifier", key32(),
                "wrappedEnvKey", env(), "keyVersion", 1), 200);

        Map<String, Object> rotated = Map.of("id", sid, "nameIndex", key32(), "nameCiphertext", env(), "valueCiphertext", env(),
                "versions", List.of(Map.of("version", 1, "nameIndex", key32(), "nameCiphertext", env(), "valueCiphertext", env())));
        // missing secrets → rejected
        call(post("/api/environments/" + env + "/rotation"), a, Map.of("expectedKeyVersion", 1,
                "grants", List.of(Map.of("userId", a.userId(), "wrappedKey", sealed())), "secrets", List.of()), 409);
        // wrong expected version → rejected
        call(post("/api/environments/" + env + "/rotation"), a, Map.of("expectedKeyVersion", 5,
                "grants", List.of(Map.of("userId", a.userId(), "wrappedKey", sealed())), "secrets", List.of(rotated)), 409);
        JsonNode r = call(post("/api/environments/" + env + "/rotation"), a, Map.of("expectedKeyVersion", 1,
                "grants", List.of(Map.of("userId", a.userId(), "wrappedKey", sealed())), "secrets", List.of(rotated)), 200);
        assertThat(r.get("newKeyVersion").asInt()).isEqualTo(2);
        assertThat(r.get("tokensRevoked").asInt()).isEqualTo(1);
        JsonNode list = call(get("/api/environments/" + env + "/secrets"), a, null, 200);
        assertThat(list.get("keyVersion").asInt()).isEqualTo(2);
        assertThat(list.at("/secrets/0/valueCiphertext").asText()).isEqualTo(rotated.get("valueCiphertext"));
    }

    // ------------------------------------------------------- service tokens

    @Test
    void serviceTokenAuthenticatesAndIsScoped() throws Exception {
        Account a = register("ci");
        Project p = createProject(a);
        String env = p.envIds().get(1);
        call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(secret(uuid()), secret(uuid()))), 200);

        byte[] authSecret = Codec.randomBytes(32);
        String tokenId = Codec.randomToken(16);
        String verifier = Codec.sha256B64u(authSecret);
        JsonNode t = call(post("/api/environments/" + env + "/tokens"), a, Map.of("tokenId", tokenId, "name", "github-actions",
                "verifier", verifier, "wrappedEnvKey", env(), "keyVersion", 1, "expiresInDays", 30), 200);

        String header = "KV-Service-Token " + tokenId + "." + Codec.b64u(authSecret);
        String body = mvc.perform(get("/api/v1/service/secrets").header("Authorization", header))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode res = json.readTree(body);
        assertThat(res.get("secrets")).hasSize(2);
        assertThat(res.get("environmentId").asText()).isEqualTo(env);

        // wrong secret
        mvc.perform(get("/api/v1/service/secrets").header("Authorization", "KV-Service-Token " + tokenId + "." + key32()))
                .andExpect(status().isUnauthorized());
        // token cannot touch user APIs
        mvc.perform(get("/api/projects").header("Authorization", header)).andExpect(status().isForbidden());

        call(delete("/api/environments/" + env + "/tokens/" + t.get("id").asText()), a, null, 204);
        mvc.perform(get("/api/v1/service/secrets").header("Authorization", header)).andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ audit

    @Test
    void auditChainDetectsTampering() throws Exception {
        Account a = register("audit");
        Project p = createProject(a);
        call(post("/api/environments/" + p.envIds().get(0) + "/secrets"), a, Map.of("secrets", List.of(secret(uuid()))), 200);
        call(get("/api/environments/" + p.envIds().get(0) + "/secrets"), a, null, 200);

        JsonNode v = call(get("/api/projects/" + p.id() + "/audit/verify"), a, null, 200);
        assertThat(v.get("valid").asBoolean()).isTrue();
        assertThat(v.get("eventsChecked").asInt()).isEqualTo(3);

        db.sql("UPDATE audit_events SET actor_label = 'someone-else' WHERE chain_key = ? AND chain_index = 2")
                .param("project:" + p.id()).update();
        JsonNode broken = call(get("/api/projects/" + p.id() + "/audit/verify"), a, null, 200);
        assertThat(broken.get("valid").asBoolean()).isFalse();
        assertThat(broken.get("firstBrokenIndex").asInt()).isEqualTo(2);
    }

    // ------------------------------------------------------------------ sends

    @Test
    void oneTimeSendBurnsAfterReading() throws Exception {
        Account a = register("send");
        String ct = env();
        JsonNode s = call(post("/api/sends"), a, Map.of("ciphertext", ct, "maxViews", 1, "expiresInMinutes", 60), 200);
        String id = s.get("id").asText();
        JsonNode opened = call(post("/api/public/sends/" + id + "/open"), null, null, 200);
        assertThat(opened.get("ciphertext").asText()).isEqualTo(ct);
        call(post("/api/public/sends/" + id + "/open"), null, null, 404);
        String stored = db.sql("SELECT ciphertext FROM sends WHERE id = ?").param(id).query(String.class).single();
        assertThat(stored).isEmpty();
    }

    // --------------------------------------------------------------- passkeys

    @Test
    void passkeyRegistrationRequiresPasswordAndIsScopedToUser() throws Exception {
        Account a = register("pk");
        Account other = register("pk2");
        Map<String, Object> body = new HashMap<>();
        body.put("currentAuthKey", key32());
        body.put("credentialId", Codec.randomToken(32));
        body.put("name", "MacBook Touch ID");
        body.put("prfSalt", key32());
        body.put("wrappedAccountKey", env());
        call(post("/api/account/passkeys"), a, body, 403); // wrong master password
        body.put("currentAuthKey", a.authKey());
        JsonNode list = call(post("/api/account/passkeys"), a, body, 200);
        assertThat(list).hasSize(1);
        String id = list.get(0).get("id").asText();
        call(post("/api/account/passkeys"), a, body, 409); // same credential twice
        call(get("/api/account/passkeys"), other, null, 200).forEach(n -> assertThat(n.get("id").asText()).isNotEqualTo(id));
        call(delete("/api/account/passkeys/" + id), other, null, 404);
        call(post("/api/account/passkeys/" + id + "/used"), a, null, 204);
        call(delete("/api/account/passkeys/" + id), a, null, 204);
        assertThat(call(get("/api/account/passkeys"), a, null, 200)).isEmpty();
    }

    // ---------------------------------------------------------------- metrics

    @Test
    void prometheusEndpointRequiresBearerToken() throws Exception {
        mvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/prometheus").header("Authorization", "Bearer wrong")).andExpect(status().isUnauthorized());
        Account a = register("metrics");
        call(post("/api/auth/login"), null, Map.of("email", a.email(), "authKey", key32()), 401);
        String body = mvc.perform(get("/actuator/prometheus").header("Authorization", "Bearer test-metrics-token"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("keyvault_auth_logins_total").contains("result=\"failure\"").contains("http_server_requests_seconds_bucket");
        assertThat(body).doesNotContain(a.email());
    }

    @Test
    void concurrentReadsAreAllAuditedAndChainStaysValid() throws Exception {
        Account a = register("burst");
        Project p = createProject(a);
        String env = p.envIds().get(0);
        var pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        var futures = new ArrayList<java.util.concurrent.Future<Integer>>();
        for (int i = 0; i < 40; i++) {
            futures.add(pool.submit(() -> mvc.perform(api(get("/api/environments/" + env + "/secrets"), a, null))
                    .andReturn().getResponse().getStatus()));
        }
        for (var f : futures) assertThat(f.get()).isEqualTo(200);
        pool.shutdown();
        JsonNode v = call(get("/api/projects/" + p.id() + "/audit/verify"), a, null, 200);
        assertThat(v.get("valid").asBoolean()).isTrue();
        assertThat(v.get("eventsChecked").asInt()).isEqualTo(41); // project.created + 40 reads
    }

    // ---------------------------------------------------------- change requests

    Map<String, Object> crItem(String op, String secretId, Integer expected) {
        Map<String, Object> m = new HashMap<>();
        m.put("op", op);
        m.put("secretId", secretId);
        m.put("expectedVersion", expected);
        if (!op.equals("DELETE")) {
            m.put("nameIndex", key32());
            m.put("nameCiphertext", env());
            m.put("valueCiphertext", env());
        }
        return m;
    }

    @Test
    void protectedEnvironmentRequiresReviewedChangeRequests() throws Exception {
        Account owner = register("cr-owner");
        Account admin = register("cr-admin");
        Account dev = register("cr-dev");
        Project p = createProject(owner);
        String prod = p.envIds().get(1); // "production" is protected by default
        JsonNode detail = call(get("/api/projects/" + p.id()), owner, null, 200);
        assertThat(detail.at("/environments/1/protected").asBoolean()).isTrue();
        for (Account a : List.of(admin, dev)) {
            call(post("/api/projects/" + p.id() + "/members"), owner, Map.of("userId", a.userId(), "role", a == admin ? "ADMIN" : "DEVELOPER",
                    "grants", List.of(Map.of("environmentId", prod, "wrappedKey", sealed()))), 200);
        }
        // developer cannot write directly
        call(post("/api/environments/" + prod + "/secrets"), dev, Map.of("secrets", List.of(secret(uuid()))), 409);

        // developer proposes; cannot approve own; admin approves → applied
        String sid = uuid();
        JsonNode cr = call(post("/api/environments/" + prod + "/change-requests"), dev,
                Map.of("title", "Add Stripe key", "keyVersion", 1, "items", List.of(crItem("CREATE", sid, null))), 200);
        assertThat(cr.get("status").asText()).isEqualTo("OPEN");
        String crId = cr.get("id").asText();
        assertThat(call(get("/api/projects/" + p.id()), owner, null, 200).at("/environments/1/openChangeRequests").asInt()).isEqualTo(1);
        call(post("/api/environments/" + prod + "/change-requests/" + crId + "/approve"), dev, Map.of(), 403);
        JsonNode applied = call(post("/api/environments/" + prod + "/change-requests/" + crId + "/approve"), admin, Map.of("comment", "lgtm"), 200);
        assertThat(applied.get("status").asText()).isEqualTo("APPLIED");
        JsonNode list = call(get("/api/environments/" + prod + "/secrets"), dev, null, 200);
        assertThat(list.get("secrets")).hasSize(1);
        assertThat(list.at("/secrets/0/id").asText()).isEqualTo(sid);
        call(post("/api/environments/" + prod + "/change-requests/" + crId + "/approve"), admin, Map.of(), 409); // already closed

        // two proposals based on v1: the second one becomes a CONFLICT instead of overwriting
        String a = call(post("/api/environments/" + prod + "/change-requests"), dev,
                Map.of("title", "Rotate", "keyVersion", 1, "items", List.of(crItem("UPDATE", sid, 1))), 200).get("id").asText();
        String b = call(post("/api/environments/" + prod + "/change-requests"), dev,
                Map.of("title", "Rotate again", "keyVersion", 1, "items", List.of(crItem("UPDATE", sid, 1))), 200).get("id").asText();
        assertThat(call(post("/api/environments/" + prod + "/change-requests/" + a + "/approve"), owner, Map.of(), 200).get("status").asText()).isEqualTo("APPLIED");
        JsonNode conflict = call(post("/api/environments/" + prod + "/change-requests/" + b + "/approve"), owner, Map.of(), 200);
        assertThat(conflict.get("status").asText()).isEqualTo("CONFLICT");
        assertThat(conflict.get("reviewComment").asText()).contains("changed meanwhile");

        // author can cancel their own open request
        String c = call(post("/api/environments/" + prod + "/change-requests"), dev,
                Map.of("title", "Delete it", "keyVersion", 1, "items", List.of(crItem("DELETE", sid, 2))), 200).get("id").asText();
        assertThat(call(post("/api/environments/" + prod + "/change-requests/" + c + "/reject"), dev, Map.of(), 200).get("status").asText()).isEqualTo("CANCELLED");
    }

    // ----------------------------------------------------------------- webhooks

    @Test
    void webhooksAreSignedRetriedAndCarryNoSecretMaterial() throws Exception {
        var received = new java.util.concurrent.LinkedBlockingQueue<Map<String, String>>();
        var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        var failFirst = new java.util.concurrent.atomic.AtomicBoolean(true);
        server.createContext("/hook", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            received.add(Map.of("body", body, "sig", ex.getRequestHeaders().getFirst("X-KeyVault-Signature"),
                    "event", ex.getRequestHeaders().getFirst("X-KeyVault-Event")));
            int code = body.contains("\"secret.updated\"") && failFirst.getAndSet(false) ? 500 : 200;
            ex.sendResponseHeaders(code, -1);
            ex.close();
        });
        server.start();
        try {
            Account a = register("hooks");
            Project p = createProject(a);
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/hook";
            JsonNode created = call(post("/api/projects/" + p.id() + "/webhooks"), a,
                    Map.of("url", url, "events", List.of("secret.created", "secret.updated")), 200);
            String signingSecret = created.get("signingSecret").asText();
            assertThat(signingSecret).startsWith("whsec_");
            String webhookId = created.at("/webhook/id").asText();

            JsonNode ping = call(post("/api/projects/" + p.id() + "/webhooks/" + webhookId + "/ping"), a, null, 200);
            assertThat(ping.get("status").asText()).isEqualTo("SUCCEEDED");
            received.poll(5, java.util.concurrent.TimeUnit.SECONDS);

            String env = p.envIds().get(0);
            Map<String, Object> s = secret(uuid());
            call(post("/api/environments/" + env + "/secrets"), a, Map.of("secrets", List.of(s)), 200);
            Map<String, String> got = received.poll(10, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(got).isNotNull();
            assertThat(got.get("event")).isEqualTo("secret.created");
            // verify the Stripe-style signature exactly as a receiver would
            String[] parts = got.get("sig").split(",");
            long t = Long.parseLong(parts[0].substring(2));
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(signingSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
            String expected = Codec.hex(mac.doFinal((t + "." + got.get("body")).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            assertThat(parts[1]).isEqualTo("v1=" + expected);
            // payload has ids only: no ciphertext, no names
            assertThat(got.get("body")).doesNotContain("kv1.").doesNotContain((String) s.get("nameIndex")).contains((String) s.get("id"));

            // first secret.updated delivery fails with 500 and is retried later (backoff)
            String sid = (String) s.get("id");
            Map<String, Object> upd = secret(sid);
            upd.remove("id");
            upd.put("expectedVersion", 1);
            call(put("/api/environments/" + env + "/secrets/" + sid), a, upd, 200);
            assertThat(received.poll(10, java.util.concurrent.TimeUnit.SECONDS).get("event")).isEqualTo("secret.updated");
            JsonNode deliveries = call(get("/api/projects/" + p.id() + "/webhooks/" + webhookId + "/deliveries"), a, null, 200);
            JsonNode failed = deliveries.get(0);
            assertThat(failed.get("event").asText()).isEqualTo("secret.updated");
            assertThat(failed.get("status").asText()).isEqualTo("PENDING");
            assertThat(failed.get("responseCode").asInt()).isEqualTo(500);
            call(post("/api/projects/" + p.id() + "/webhooks/deliveries/" + failed.get("id").asText() + "/redeliver"), a, null, 202);
            assertThat(received.poll(10, java.util.concurrent.TimeUnit.SECONDS)).isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void webhookUrlsAreCheckedForSsrf() {
        var strict = new dev.keyvault.webhook.WebhookService(null, null, new org.springframework.jdbc.support.JdbcTransactionManager(), false, false) {
            void check(String u) { this.validateUrl(u, true); }
        };
        for (String bad : List.of("http://example.com/x", "https://127.0.0.1/x", "https://10.0.0.5/x", "https://169.254.169.254/latest/meta-data",
                "https://192.168.1.1/x", "https://[::1]/x", "ftp://example.com", "https://user:pw@example.com/")) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> strict.check(bad)).as(bad).isInstanceOf(dev.keyvault.common.ApiException.class);
        }
    }
}
