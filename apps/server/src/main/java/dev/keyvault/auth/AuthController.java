package dev.keyvault.auth;

import dev.keyvault.audit.AuditService;
import dev.keyvault.auth.AuthDtos.*;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService auth;
    private final SessionService sessions;
    private final UserRepository users;
    private final AuditService audit;

    public AuthController(AuthService auth, SessionService sessions, UserRepository users, AuditService audit) {
        this.auth = auth;
        this.sessions = sessions;
        this.users = users;
        this.audit = audit;
    }

    @PostMapping("/prelogin")
    public PreloginResponse prelogin(@Valid @RequestBody PreloginRequest req, HttpServletRequest http) {
        return auth.prelogin(req.email(), ClientInfo.of(http));
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest http) {
        return withSession(auth.register(req, ClientInfo.of(http)));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        return withSession(auth.login(req, ClientInfo.of(http)));
    }

    @PostMapping("/login/mfa")
    public ResponseEntity<LoginResponse> mfa(@Valid @RequestBody MfaRequest req, HttpServletRequest http) {
        return withSession(auth.completeMfa(req, ClientInfo.of(http)));
    }

    /** Returns the encrypted key bundle so a reloaded tab can show the "unlock" screen. */
    @GetMapping("/session")
    public SessionResponse session() {
        return SessionResponse.of(users.require(Principals.user().userId()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        var p = Principals.user();
        sessions.revoke(p.userId(), p.sessionId());
        audit.record(AuditService.Event.of(AuditService.Actor.user(p.userId(), p.email()), null, "auth.logout"));
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, sessions.clearCookie().toString()).build();
    }

    @PostMapping("/recover/start")
    public RecoverStartResponse recoverStart(@Valid @RequestBody RecoverStartRequest req, HttpServletRequest http) {
        return auth.recoverStart(req, ClientInfo.of(http));
    }

    @PostMapping("/recover/complete")
    public ResponseEntity<Void> recoverComplete(@Valid @RequestBody RecoverCompleteRequest req) {
        auth.recoverComplete(req);
        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<LoginResponse> withSession(AuthService.LoginOutcome outcome) {
        var res = ResponseEntity.ok();
        if (outcome.sessionToken() != null) {
            res.header(HttpHeaders.SET_COOKIE, sessions.cookie(outcome.sessionToken()).toString());
        }
        return res.body(outcome.body());
    }
}
