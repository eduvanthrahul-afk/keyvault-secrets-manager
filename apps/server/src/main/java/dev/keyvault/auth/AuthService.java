package dev.keyvault.auth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.keyvault.audit.AuditService;
import dev.keyvault.audit.AuditService.Actor;
import dev.keyvault.audit.AuditService.Event;
import dev.keyvault.auth.AuthDtos.*;
import dev.keyvault.common.ApiException;
import dev.keyvault.common.ClientInfo;
import dev.keyvault.common.Codec;
import dev.keyvault.common.RateLimiter;
import dev.keyvault.common.RateLimiter.Policy;
import dev.keyvault.common.ServerCrypto;
import dev.keyvault.config.KeyVaultProperties;
import dev.keyvault.user.UserRecord;
import dev.keyvault.user.UserRepository;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The server never receives the master password. It receives authKey = HKDF(Argon2id(password)),
 * and stores Argon2id(authKey) on top, so a stolen database cannot be replayed as a login and
 * every password guess costs two Argon2id evaluations.
 */
@Service
public class AuthService {
    private static final String INVALID_CREDENTIALS = "Invalid email or password";

    private final UserRepository users;
    private final SessionService sessions;
    private final TotpService totp;
    private final AuditService audit;
    private final RateLimiter limiter;
    private final ServerCrypto serverCrypto;
    private final KeyVaultProperties props;
    private final dev.keyvault.common.KeyVaultMetrics metrics;
    /** Server-side Argon2id over the already-stretched authKey (OWASP: m=12 MiB, t=3, p=1). */
    private final Argon2PasswordEncoder hasher = new Argon2PasswordEncoder(16, 32, 1, 12288, 3);
    private final String dummyHash = hasher.encode(Codec.randomToken(32));

    private record Challenge(UUID userId, AtomicInteger attempts) {}

    private final Cache<String, Challenge> mfaChallenges = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(5)).maximumSize(50_000).build();
    private final Cache<String, UUID> recoveryTickets = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10)).maximumSize(10_000).build();

    public AuthService(UserRepository users, SessionService sessions, TotpService totp, AuditService audit,
                       RateLimiter limiter, ServerCrypto serverCrypto, KeyVaultProperties props,
                       dev.keyvault.common.KeyVaultMetrics metrics) {
        this.metrics = metrics;
        this.users = users;
        this.sessions = sessions;
        this.totp = totp;
        this.audit = audit;
        this.limiter = limiter;
        this.serverCrypto = serverCrypto;
        this.props = props;
    }

    public record LoginOutcome(LoginResponse body, String sessionToken) {}

    static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Returns KDF parameters. For unknown emails we return a deterministic fake salt so the
     * response is indistinguishable from a real account (prevents user enumeration).
     */
    public PreloginResponse prelogin(String rawEmail, ClientInfo client) {
        limiter.check(Policy.LOGIN_IP, client.ip());
        String email = normalizeEmail(rawEmail);
        return users.findByEmail(email)
                .map(u -> new PreloginResponse(KdfDto.of(u.kdf()), u.salt()))
                .orElseGet(() -> new PreloginResponse(KdfDto.of(UserRecord.Kdf.DEFAULT),
                        Codec.b64u(Arrays.copyOf(serverCrypto.mac("fake-salt:" + email), 16))));
    }

    @Transactional
    public LoginOutcome register(RegisterRequest req, ClientInfo client) {
        if (!props.registrationEnabled()) throw ApiException.forbidden("Registration is disabled on this server");
        limiter.check(Policy.REGISTER_IP, client.ip());
        if (!req.kdf().toKdf().isAcceptable()) throw ApiException.badRequest("KDF parameters below the security minimum");
        String email = normalizeEmail(req.email());
        if (users.emailExists(email)) {
            throw ApiException.conflict("email_taken", "An account with this email already exists");
        }
        UserRecord user = new UserRecord(UUID.randomUUID(), email, req.displayName().trim(), hasher.encode(req.authKey()),
                req.kdf().toKdf(), req.salt(), req.protectedAccountKey(), req.publicKey(), req.protectedPrivateKey(),
                Codec.sha256B64u(Codec.fromB64u(req.recoveryVerifier())), req.recoveryProtectedAccountKey(),
                null, false, 0, null);
        users.insert(user);
        audit.record(Event.of(Actor.user(user.id(), email), null, "account.created"));
        metrics.registrations().increment();
        String token = sessions.create(user.id(), client);
        return new LoginOutcome(new LoginResponse(false, null, SessionResponse.of(users.require(user.id()))), token);
    }

    public LoginOutcome login(LoginRequest req, ClientInfo client) {
        String email = normalizeEmail(req.email());
        limiter.check(Policy.LOGIN_IP, client.ip());
        limiter.check(Policy.LOGIN_ACCOUNT, email);

        UserRecord user = users.findByEmail(email).orElse(null);
        if (user == null) {
            hasher.matches(req.authKey(), dummyHash); // equalise timing with the real path
            metrics.login("failure");
            throw ApiException.unauthorized(INVALID_CREDENTIALS);
        }
        if (!hasher.matches(req.authKey(), user.authHash())) {
            audit.record(Event.of(Actor.user(user.id(), email), null, "auth.login_failed"));
            metrics.login("failure");
            throw ApiException.unauthorized(INVALID_CREDENTIALS);
        }
        limiter.reset(Policy.LOGIN_ACCOUNT, email);

        if (user.totpEnabled()) {
            String mfaToken = Codec.randomToken(32);
            mfaChallenges.put(Codec.sha256Hex(mfaToken), new Challenge(user.id(), new AtomicInteger()));
            return new LoginOutcome(new LoginResponse(true, mfaToken, null), null);
        }
        return startSession(user, client, "password");
    }

    public LoginOutcome completeMfa(MfaRequest req, ClientInfo client) {
        limiter.check(Policy.MFA, client.ip());
        String key = Codec.sha256Hex(req.mfaToken());
        Challenge ch = mfaChallenges.getIfPresent(key);
        if (ch == null) throw ApiException.unauthorized("Sign-in attempt expired. Start again.");
        if (ch.attempts().incrementAndGet() > 5) {
            mfaChallenges.invalidate(key);
            throw ApiException.unauthorized("Too many incorrect codes. Start again.");
        }
        UserRecord user = users.require(ch.userId());
        String code = req.code().trim();
        boolean ok = code.matches("^\\d{6}$") ? totp.verifyAndConsume(user, code) : totp.consumeRecoveryCode(user, code);
        if (!ok) {
            audit.record(Event.of(Actor.user(user.id(), user.email()), null, "auth.mfa_failed"));
            metrics.login("mfa_failure");
            throw ApiException.unauthorized("Incorrect verification code");
        }
        mfaChallenges.invalidate(key);
        return startSession(user, client, code.matches("^\\d{6}$") ? "totp" : "recovery_code");
    }

    private LoginOutcome startSession(UserRecord user, ClientInfo client, String method) {
        String token = sessions.create(user.id(), client);
        metrics.login("success");
        audit.record(Event.of(Actor.user(user.id(), user.email()), null, "auth.login").details(Map.of("method", method)));
        return new LoginOutcome(new LoginResponse(false, null, SessionResponse.of(user)), token);
    }

    public RecoverStartResponse recoverStart(RecoverStartRequest req, ClientInfo client) {
        limiter.check(Policy.RECOVERY, client.ip());
        String email = normalizeEmail(req.email());
        limiter.check(Policy.RECOVERY, email);
        UserRecord user = users.findByEmail(email).orElse(null);
        String presented = Codec.sha256B64u(Codec.fromB64u(req.recoveryVerifier()));
        if (user == null || !Codec.constantTimeEquals(presented, user.recoveryVerifierHash())) {
            if (user != null) audit.record(Event.of(Actor.user(user.id(), email), null, "auth.recovery_failed"));
            throw ApiException.unauthorized("Recovery key does not match this account");
        }
        String ticket = Codec.randomToken(32);
        recoveryTickets.put(Codec.sha256Hex(ticket), user.id());
        return new RecoverStartResponse(ticket, user.recoveryProtectedAccountKey(), user.publicKey(), user.protectedPrivateKey());
    }

    @Transactional
    public void recoverComplete(RecoverCompleteRequest req) {
        if (!req.kdf().toKdf().isAcceptable()) throw ApiException.badRequest("KDF parameters below the security minimum");
        String key = Codec.sha256Hex(req.recoveryToken());
        UUID userId = recoveryTickets.getIfPresent(key);
        if (userId == null) throw ApiException.unauthorized("Recovery session expired. Start again.");
        recoveryTickets.invalidate(key);
        UserRecord user = users.require(userId);
        users.updatePassword(userId, hasher.encode(req.authKey()), req.kdf().toKdf(), req.salt(), req.protectedAccountKey());
        users.updateRecovery(userId, Codec.sha256B64u(Codec.fromB64u(req.recoveryVerifier())), req.recoveryProtectedAccountKey());
        sessions.revokeAll(userId, null);
        audit.record(Event.of(Actor.user(userId, user.email()), null, "account.recovered"));
    }

    /** "Sudo mode" check for sensitive account changes: the user must prove the password again. */
    public UserRecord reauthenticate(UUID userId, String currentAuthKey) {
        UserRecord user = users.require(userId);
        limiter.check(Policy.LOGIN_ACCOUNT, user.email());
        if (!hasher.matches(currentAuthKey, user.authHash())) {
            audit.record(Event.of(Actor.user(user.id(), user.email()), null, "auth.reauth_failed"));
            throw new ApiException(HttpStatus.FORBIDDEN, "reauth_failed", "Current master password is incorrect");
        }
        return user;
    }

    @Transactional
    public void changePassword(Principals.UserPrincipal p, ChangePasswordRequest req) {
        UserRecord user = reauthenticate(p.userId(), req.currentAuthKey());
        if (!req.kdf().toKdf().isAcceptable()) throw ApiException.badRequest("KDF parameters below the security minimum");
        users.updatePassword(user.id(), hasher.encode(req.authKey()), req.kdf().toKdf(), req.salt(), req.protectedAccountKey());
        int revoked = sessions.revokeAll(user.id(), p.sessionId());
        audit.record(Event.of(Actor.user(user.id(), user.email()), null, "account.password_changed")
                .details(Map.of("otherSessionsRevoked", revoked)));
    }

    @Transactional
    public void rotateRecovery(Principals.UserPrincipal p, RotateRecoveryRequest req) {
        UserRecord user = reauthenticate(p.userId(), req.currentAuthKey());
        users.updateRecovery(user.id(), Codec.sha256B64u(Codec.fromB64u(req.recoveryVerifier())), req.recoveryProtectedAccountKey());
        audit.record(Event.of(Actor.user(user.id(), user.email()), null, "account.recovery_key_rotated"));
    }
}
