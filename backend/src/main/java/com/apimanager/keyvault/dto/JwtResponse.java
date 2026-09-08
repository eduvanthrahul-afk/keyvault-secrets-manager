package com.apimanager.keyvault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {
    private String token;
    private String email;
    private String salt;
    private String publicKey;
    private String encryptedPrivateKey;
}
