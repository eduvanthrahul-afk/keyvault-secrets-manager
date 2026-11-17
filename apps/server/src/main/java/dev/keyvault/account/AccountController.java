package dev.keyvault.account;

import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.audit.AuditService.EventView;
import dev.keyvault.auth.AuthDtos.*;
import dev.keyvault.auth.AuthService;
import dev.keyvault.auth.Principals;
import dev.keyvault.auth.SessionService;
import dev.keyvault.auth.SessionService.SessionView;
import dev.keyvault.auth.TotpService;
import dev.keyvault.common.ApiException;
import dev.keyvault.user.UserRecord;
import dev.keyvault.user.UserRepository;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/account")
public class AccountController {
    private final UserRepository users;
    private final SessionService sessions;
    private final TotpService totp;
    private final AuthService auth;
    private final AuditService audit;
    private final JdbcClient db;

    public AccountController(UserRepository users, SessionService sessions, TotpService totp, AuthService auth,
                             AuditService audit, JdbcClient db) {
        this.users = users;
        this.sessions = sessions;
        this.totp = totp;
        this.auth = auth;
        this.audit = audit;
        this.db = db;
    }

    private static Actor actor(Principals.UserPrincipal p) { return Actor.user(p.userId(), p.email()); }

    public record AccountOverview(UserRecord.Profile profile, int recoveryCodesRemaining, int activeSessions) {}

    @GetMapping
    public AccountOverview me() {
        var p = Principals.user();
        UserRecord u = users.require(p.userId());
        return new AccountOverview(u.profile(), users.remainingRecoveryCodes(u.id()), sessions.list(u.id(), p.sessionId()).size());
    }

    @PatchMapping("/profile")
    public UserRecord.Profile updateProfile(@Valid @RequestBody UpdateProfileRequest req) {
        var p = Principals.user();
        users.updateDisplayName(p.userId(), req.displayName().trim());
        return users.require(p.userId()).profile();
    }

    @PostMapping("/password")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequest req) {
        auth.changePassword(Principals.user(), req);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/recovery-key")
    public ResponseEntity<Void> rotateRecovery(@Valid @RequestBody RotateRecoveryRequest req) {
        auth.rotateRecovery(Principals.user(), req);
        return ResponseEntity.noContent().build();
    }

    // ---------------------------------------------------------------- sessions

    @GetMapping("/sessions")
    public List<SessionView> sessions() {
        var p = Principals.user();
        return sessions.list(p.userId(), p.sessionId());
    }

    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<Void> revokeSession(@PathVariable UUID id) {
        var p = Principals.user();
        if (!sessions.revoke(p.userId(), id)) throw ApiException.notFound("Session");
        audit.record(Event.of(actor(p), null, "auth.session_revoked").target("session", id));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/sessions/revoke-others")
    public Map<String, Integer> revokeOthers() {
        var p = Principals.user();
        int n = sessions.revokeAll(p.userId(), p.sessionId());
        audit.record(Event.of(actor(p), null, "auth.sessions_revoked").details(Map.of("count", n)));
        return Map.of("revoked", n);
    }

    // -------------------------------------------------------------------- TOTP

    @PostMapping("/totp/setup")
    public TotpService.Setup totpSetup(@Valid @RequestBody ReauthRequest req) {
        var p = Principals.user();
        UserRecord u = auth.reauthenticate(p.userId(), req.currentAuthKey());
        if (u.totpEnabled()) throw ApiException.conflict("totp_enabled", "Two-factor authentication is already on");
        return totp.beginSetup(u);
    }

    @PostMapping("/totp/enable")
    @Transactional
    public Map<String, List<String>> totpEnable(@Valid @RequestBody TotpCodeRequest req) {
        var p = Principals.user();
        UserRecord u = users.require(p.userId());
        if (u.totpEnabled()) throw ApiException.conflict("totp_enabled", "Two-factor authentication is already on");
        if (!totp.verifyAndConsume(u, req.code())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_code", "That code didn't match. Check your device clock and try again.");
        }
        users.enableTotp(u.id());
        List<String> codes = totp.issueRecoveryCodes(u);
        audit.record(Event.of(actor(p), null, "account.totp_enabled"));
        return Map.of("recoveryCodes", codes);
    }

    @PostMapping("/totp/disable")
    @Transactional
    public ResponseEntity<Void> totpDisable(@Valid @RequestBody ReauthRequest req) {
        var p = Principals.user();
        UserRecord u = auth.reauthenticate(p.userId(), req.currentAuthKey());
        if (!u.totpEnabled()) throw ApiException.conflict("totp_disabled", "Two-factor authentication is not on");
        String code = req.code() == null ? "" : req.code().trim();
        boolean ok = code.matches("^\\d{6}$") ? totp.verifyAndConsume(u, code) : totp.consumeRecoveryCode(u, code);
        if (!ok) throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_code", "Incorrect verification code");
        users.disableTotp(u.id());
        audit.record(Event.of(actor(p), null, "account.totp_disabled"));
        return ResponseEntity.noContent().build();
    }

    // ---------------------------------------------------------------- activity

    @GetMapping("/activity")
    public List<EventView> activity(@RequestParam(required = false) Long before, @RequestParam(defaultValue = "50") int limit) {
        return audit.list("user:" + Principals.user().userId(), before, limit);
    }

    @GetMapping("/activity/verify")
    public AuditService.VerifyResult verifyActivity() {
        return audit.verify("user:" + Principals.user().userId());
    }

    // ---------------------------------------------------------------- deletion

    /**
     * Deletes the account. Projects where the user is the only member are deleted with it; projects
     * that still have other members must first be handed to another owner.
     */
    @PostMapping("/delete")
    @Transactional
    public ResponseEntity<Void> deleteAccount(@Valid @RequestBody ReauthRequest req) {
        var p = Principals.user();
        UserRecord u = auth.reauthenticate(p.userId(), req.currentAuthKey());
        List<String> blocking = db.sql("""
                SELECT pr.name FROM projects pr JOIN project_members m ON m.project_id = pr.id
                WHERE m.user_id = ? AND m.role = 'OWNER'
                  AND NOT EXISTS (SELECT 1 FROM project_members o WHERE o.project_id = pr.id AND o.role = 'OWNER' AND o.user_id <> ?)
                  AND EXISTS (SELECT 1 FROM project_members o WHERE o.project_id = pr.id AND o.user_id <> ?)
                """).params(u.id(), u.id(), u.id()).query(String.class).list();
        if (!blocking.isEmpty()) {
            throw ApiException.conflict("owner_of_shared_projects",
                    "Transfer ownership first. You are the only owner of: " + String.join(", ", blocking));
        }
        db.sql("""
                DELETE FROM projects WHERE id IN (
                  SELECT m.project_id FROM project_members m WHERE m.user_id = ?
                  AND NOT EXISTS (SELECT 1 FROM project_members o WHERE o.project_id = m.project_id AND o.user_id <> ?))
                """).params(u.id(), u.id()).update();
        db.sql("UPDATE environments SET rotation_needed = TRUE WHERE id IN (SELECT environment_id FROM environment_key_grants WHERE user_id = ?)")
                .param(u.id()).update();
        audit.record(Event.of(actor(p), null, "account.deleted"));
        users.delete(u.id()); // cascades sessions, grants, memberships, sends
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, sessions.clearCookie().toString()).build();
    }
}
