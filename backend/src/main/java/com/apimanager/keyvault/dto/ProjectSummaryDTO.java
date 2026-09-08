package com.apimanager.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class ProjectSummaryDTO {
    private UUID id;
    private String name;
    private String tag;
    private String ownerEmail;
    private String userRole;
    private String encryptedProjectKey;
    private long keyCount;
    private long expiringKeyCount;
}
