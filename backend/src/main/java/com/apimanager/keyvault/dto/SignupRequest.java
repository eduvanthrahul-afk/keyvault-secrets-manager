package com.apimanager.keyvault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 100, message = "Email is too long")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 12, max = 128, message = "Password must be between 12 and 128 characters")
    private String password;

    @NotBlank(message = "Salt is required")
    private String salt; // Client-side generated salt for key derivation

    @NotBlank(message = "Public key is required")
    private String publicKey;

    @NotBlank(message = "Private key bundle is required")
    private String encryptedPrivateKey;
}
