package com.apimanager.keyvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.time.LocalDate;
import java.util.UUID;

@Data
public class ApiKeyDTO {
    private UUID id;

    @NotNull(message = "Project context is required")
    private UUID projectId;

    @NotBlank(message = "Secret name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;

    @Size(max = 50, message = "Service identifier too long")
    private String service;

    @Size(max = 50, message = "Environment identifier too long")
    private String environment;

    @NotBlank(message = "Ciphertext is required")
    private String encryptedValue;

    @NotBlank(message = "Initialization vector is required")
    private String iv;

    private LocalDate expiryDate;

    @Size(max = 500, message = "Notes too long")
    private String notes;

    private int version;
}
