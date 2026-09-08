package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.JwtResponse;
import com.apimanager.keyvault.dto.LoginRequest;
import com.apimanager.keyvault.dto.SignupRequest;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.UserRepository;
import com.apimanager.keyvault.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Error: Email is already in use!"));
        }

        User user = User.builder()
                .email(signUpRequest.getEmail())
                .passwordHash(encoder.encode(signUpRequest.getPassword()))
                .salt(signUpRequest.getSalt())
                .publicKey(signUpRequest.getPublicKey())
                .encryptedPrivateKey(signUpRequest.getEncryptedPrivateKey())
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();

        return ResponseEntity.ok(new JwtResponse(jwt, user.getEmail(), user.getSalt(), user.getPublicKey(),
                user.getEncryptedPrivateKey()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication.getPrincipal().equals("anonymousUser")) {
            return ResponseEntity.status(401).body(Map.of("message", "Error: Not authenticated"));
        }

        String jwt = jwtUtils.generateJwtToken(authentication);
        String email = authentication.getName();
        User user = userRepository.findByEmail(email).orElseThrow();

        return ResponseEntity.ok(new JwtResponse(jwt, user.getEmail(), user.getSalt(), user.getPublicKey(),
                user.getEncryptedPrivateKey()));
    }
}
