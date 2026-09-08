package com.apimanager.keyvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.util.UUID;

@Data
public class ProjectDTO {
    private UUID id;

    @NotBlank(message = "Workspace name is required")
    @Size(min = 2, max = 50, message = "Workspace name must be between 2 and 50 characters")
    private String name;

    @Size(max = 20, message = "Tag is too long")
    private String tag;

    private String ownerEmail;
    private String encryptedProjectKey;
    private long keyCount;
    private long expiringKeyCount;
}
