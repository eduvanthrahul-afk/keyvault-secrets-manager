package dev.keyvault.secret;

import dev.keyvault.common.Validation;
import dev.keyvault.project.ProjectDtos.GrantInput;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class SecretDtos {
    private SecretDtos() {}

    public record SecretInput(
            @NotBlank @Pattern(regexp = Validation.UUID) String id,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String nameIndex,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String nameCiphertext,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String valueCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String commentCiphertext,
            int keyVersion) {}

    public record BulkCreateRequest(@NotNull @Size(min = 1, max = 500) List<@Valid SecretInput> secrets) {}

    public record UpdateSecretRequest(
            int expectedVersion,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String nameIndex,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String nameCiphertext,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String valueCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String commentCiphertext,
            int keyVersion) {}

    public record RollbackRequest(int toVersion, int expectedVersion) {}

    public record SecretView(UUID id, String nameCiphertext, String valueCiphertext, String commentCiphertext, int version,
                             int keyVersion, Instant createdAt, Instant updatedAt, String updatedBy) {}

    public record EnvironmentSecrets(UUID projectId, UUID environmentId, String environmentName, int keyVersion,
                                     List<SecretView> secrets) {}

    public record VersionView(int version, String nameCiphertext, String valueCiphertext, String commentCiphertext,
                              int keyVersion, String changeType, String changedBy, Instant createdAt) {}

    public record RotatedVersion(
            int version,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String nameIndex,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String nameCiphertext,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String valueCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String commentCiphertext) {}

    public record RotatedSecret(
            @NotBlank @Pattern(regexp = Validation.UUID) String id,
            @NotBlank @Pattern(regexp = Validation.KEY_32) String nameIndex,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String nameCiphertext,
            @NotBlank @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_VALUE_CT) String valueCiphertext,
            @Pattern(regexp = Validation.ENVELOPE) @Size(max = Validation.MAX_SMALL_CT) String commentCiphertext,
            @NotNull @Size(max = 1000) List<@Valid RotatedVersion> versions) {}

    /**
     * Client-side key rotation: the admin's browser decrypts everything with the old key, generates
     * a fresh environment key, re-encrypts all secrets and history, and re-seals the key for the
     * members who should keep access. The server swaps it all in one transaction.
     */
    public record RotateRequest(
            int expectedKeyVersion,
            @NotNull @Size(min = 1, max = 500) List<@Valid GrantInput> grants,
            @NotNull @Size(max = 2000) List<@Valid RotatedSecret> secrets) {}

    public record RotateResult(int newKeyVersion, int secretsReencrypted, int membersWithAccess, int tokensRevoked) {}
}
