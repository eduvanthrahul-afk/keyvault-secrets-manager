package dev.keyvault.auth;

import dev.keyvault.common.Validation;
import dev.keyvault.user.UserRecord;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AuthDtos {
    private AuthDtos() {}

    public record KdfDto(@NotBlank String algorithm, int memoryKiB, int iterations, int parallelism) {
        public UserRecord.Kdf toKdf() { return new UserRecord.Kdf(algorithm, memoryKiB, iterations, parallelism); }
        public static KdfDto of(UserRecord.Kdf k) { return new KdfDto(k.algorithm(), k.memoryKiB(), k.iterations(), k.parallelism()); }
    }

    public record PreloginRequest(@NotBlank @Email @Size(max = 320) String email) {}

    public record PreloginResponse(KdfDto kdf, String salt) {}

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 1, max = 80) String displayName,
            @NotNull @Valid KdfDto kdf,
            @NotBlank @Pattern(regexp = Validation.B64U) @Size(min = 22, max = 64) String salt,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String authKey,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String protectedAccountKey,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String publicKey,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String protectedPrivateKey,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String recoveryVerifier,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String recoveryProtectedAccountKey) {}

    public record LoginRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String authKey) {}

    public record MfaRequest(@NotBlank @Size(max = 64) String mfaToken, @NotBlank @Size(max = 32) String code) {}

    /** Either a full session (keys present) or an MFA challenge. */
    public record LoginResponse(boolean mfaRequired, String mfaToken, SessionResponse session) {}

    public record SessionResponse(UserRecord.Profile user, KdfDto kdf, String salt, String protectedAccountKey,
                                  String publicKey, String protectedPrivateKey) {
        public static SessionResponse of(UserRecord u) {
            return new SessionResponse(u.profile(), KdfDto.of(u.kdf()), u.salt(), u.protectedAccountKey(), u.publicKey(),
                    u.protectedPrivateKey());
        }
    }

    public record RecoverStartRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String recoveryVerifier) {}

    public record RecoverStartResponse(String recoveryToken, String recoveryProtectedAccountKey, String publicKey,
                                       String protectedPrivateKey) {}

    public record RecoverCompleteRequest(
            @NotBlank @Size(max = 64) String recoveryToken,
            @NotNull @Valid KdfDto kdf,
            @NotBlank @Pattern(regexp = Validation.B64U) @Size(min = 22, max = 64) String salt,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String authKey,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String protectedAccountKey,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String recoveryVerifier,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String recoveryProtectedAccountKey) {}

    public record ChangePasswordRequest(
            @NotBlank @Pattern(regexp = Validation.KEY_32) String currentAuthKey,
            @NotNull @Valid KdfDto kdf,
            @NotBlank @Pattern(regexp = Validation.B64U) @Size(min = 22, max = 64) String salt,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String authKey,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String protectedAccountKey) {}

    public record RotateRecoveryRequest(
            @NotBlank @Pattern(regexp = Validation.KEY_32) String currentAuthKey,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String recoveryVerifier,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String recoveryProtectedAccountKey) {}

    public record ReauthRequest(@NotBlank @Pattern(regexp = Validation.KEY_32) String currentAuthKey, String code) {}

    public record TotpCodeRequest(@NotBlank @Pattern(regexp = "^\\d{6}$") String code) {}

    public record UpdateProfileRequest(@NotBlank @Size(min = 1, max = 80) String displayName) {}
}
