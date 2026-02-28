package com.apimanager.keyvault.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class AuditLogDTO {
    private UUID id;
    private UUID projectId;
    private String userEmail;
    private String action;
    private String targetType;
    private String targetId;
    private String details;
    private String ipAddress;
    private LocalDateTime createdAt;
}
