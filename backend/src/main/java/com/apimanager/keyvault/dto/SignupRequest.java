package com.apimanager.keyvault.dto;

import lombok.Data;

@Data
public class SignupRequest {
    private String email;
    private String password;
    private String salt; // Client-side generated salt for key derivation
    private String publicKey;
    private String encryptedPrivateKey;
}
