package com.apimanager.keyvault.dto;

import lombok.Builder;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class MachineTokenDTO {
    private UUID id;
    private String name;
    private String tokenId;
    private LocalDateTime createdAt;
    // We never return the hash or the encrypted key in the list view for security
    // hygiene
}
