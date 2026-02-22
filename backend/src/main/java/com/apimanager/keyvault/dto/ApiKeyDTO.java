package com.apimanager.keyvault.dto;

import lombok.Data;
import java.time.LocalDate;
import java.util.UUID;

@Data
public class ApiKeyDTO {
    private UUID id;
    private UUID projectId;
    private String name;
    private String service;
    private String environment;
    private String encryptedValue;
    private String iv;
    private LocalDate expiryDate;
    private String notes;
}
