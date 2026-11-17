package dev.keyvault.project;

import dev.keyvault.common.Validation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class ProjectDtos {
    private ProjectDtos() {}

    public record GrantInput(
            @NotBlank @Pattern(regexp = Validation.UUID) String userId,
            @NotBlank @Pattern(regexp = Validation.SEALED) @Size(max = 400) String wrappedKey) {}

    public record EnvGrantInput(
            @NotBlank @Pattern(regexp = Validation.UUID) String environmentId,
            @NotBlank @Pattern(regexp = Validation.SEALED) @Size(max = 400) String wrappedKey) {}

    public record NewEnvironment(
            @NotBlank @Pattern(regexp = Validation.UUID) String id,
            @NotBlank @Size(max = 40) String name,
            @NotBlank @Pattern(regexp = Validation.SLUG) String slug,
            @NotBlank @Pattern(regexp = Validation.SEALED) @Size(max = 400) String wrappedKey) {}

    public record CreateProjectRequest(
            @NotBlank @Pattern(regexp = Validation.UUID) String id,
            @NotBlank @Size(max = 80) String name,
            @Size(max = 500) String description,
            @NotNull @Size(min = 1, max = 10) List<@Valid NewEnvironment> environments) {}

    public record UpdateProjectRequest(@NotBlank @Size(max = 80) String name, @Size(max = 500) String description) {}

    public record DeleteProjectRequest(@NotBlank String confirmName) {}

    public record CreateEnvironmentRequest(
            @NotBlank @Pattern(regexp = Validation.UUID) String id,
            @NotBlank @Size(max = 40) String name,
            @NotBlank @Pattern(regexp = Validation.SLUG) String slug,
            @NotNull @Size(min = 1, max = 500) List<@Valid GrantInput> grants) {}

    public record RenameEnvironmentRequest(@NotBlank @Size(max = 40) String name) {}

    public record AddMemberRequest(
            @NotBlank @Pattern(regexp = Validation.UUID) String userId,
            @NotNull Role role,
            @NotNull @Size(max = 10) List<@Valid EnvGrantInput> grants) {}

    public record ChangeRoleRequest(@NotNull Role role) {}

    public record SetGrantRequest(
            @NotBlank @Pattern(regexp = Validation.SEALED) @Size(max = 400) String wrappedKey,
            int keyVersion) {}

    // ---- views

    public record ProjectSummary(UUID id, String name, String description, Role role, int environmentCount,
                                 int memberCount, int secretCount, boolean rotationNeeded, Instant createdAt, Instant updatedAt) {}

    public record EnvironmentView(UUID id, String name, String slug, int position, int keyVersion, boolean rotationNeeded,
                                  int secretCount, int tokenCount, String wrappedKey, Integer grantKeyVersion,
                                  @com.fasterxml.jackson.annotation.JsonProperty("protected") boolean protectedEnv,
                                  int openChangeRequests) {}

    public record ProtectionRequest(boolean enabled) {}

    public record MemberView(UUID userId, String email, String displayName, String publicKey, Role role,
                             List<UUID> environmentIds, Instant joinedAt) {}

    public record ProjectDetail(UUID id, String name, String description, Role role, Instant createdAt,
                                List<EnvironmentView> environments, List<MemberView> members) {}

    public record UserLookup(UUID id, String email, String displayName, String publicKey) {}
}
