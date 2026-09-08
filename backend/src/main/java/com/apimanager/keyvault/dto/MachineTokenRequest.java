package com.apimanager.keyvault.dto;

import lombok.Data;

@Data
public class MachineTokenRequest {
    private String name;
    private String tokenId;
    private String tokenHash;
    private String encryptedProjectKey;
}
