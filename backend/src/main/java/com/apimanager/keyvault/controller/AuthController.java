package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.JwtResponse;
import com.apimanager.keyvault.dto.LoginRequest;
import com.apimanager.keyvault.dto.SignupRequest;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.UserRepository;
import com.apimanager.keyvault.security.JwtUtils;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

        @Autowired
        private com.apimanager.keyvault.service.RateLimitService rateLimitService;

        @Autowired
        private jakarta.servlet.http.HttpServletRequest request;

        @Autowired
        private com.apimanager.keyvault.service.OtpService otpService;

        @Autowired
        private com.apimanager.keyvault.service.EmailService emailService;

        @Autowired
        private com.apimanager.keyvault.service.TokenBlacklistService tokenBlacklistService;

        @Value("${app.testing.otp-required:true}")
        private boolean otpRequired;

        @PostMapping("/otp/send")
        public ResponseEntity<?> sendOtp(@RequestBody Map<String, String> requestBody) {
                String email = requestBody.get("email");
                if (email == null || email.isEmpty()) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
                }

                String normalizedEmail = email.toLowerCase().trim();
                String clientIp = request.getRemoteAddr();
                String rateLimitKey = "otp_send_" + clientIp + "_" + normalizedEmail;

                if (!rateLimitService.resolveKeyBucket(rateLimitKey).tryConsume(1)) {
                        return ResponseEntity.status(429)
                                        .body(Map.of("message", "Too many OTP requests. Please wait a minute."));
                }

                if (userRepository.existsByEmail(normalizedEmail)) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Error: Email is already in use!"));
                }

                String otp = otpService.generateOtp(normalizedEmail);
                emailService.sendOtpEmail(normalizedEmail, otp);

                return ResponseEntity.ok(Map.of("message", "Verification code sent to " + normalizedEmail));
        }

        @PostMapping("/otp/verify")
        public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> requestBody) {
                String email = requestBody.get("email");
                String code = requestBody.get("code");

                if (email == null || code == null) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Email and code are required"));
                }

                String normalizedEmail = email.toLowerCase().trim();
                String clientIp = request.getRemoteAddr();
                String rateLimitKey = "otp_verify_" + clientIp + "_" + normalizedEmail;

                if (!rateLimitService.resolveKeyBucket(rateLimitKey).tryConsume(1)) {
                        return ResponseEntity.status(429)
                                        .body(Map.of("message", "Too many verification attempts. Please wait."));
                }

                if (otpService.verifyOtp(normalizedEmail, code)) {
                        return ResponseEntity.ok(Map.of("message", "OTP Verified", "success", true));
                } else {
                        return ResponseEntity.status(401)
                                        .body(Map.of("message", "Invalid or expired verification code"));
                }
        }

        @GetMapping("/salt")
        public ResponseEntity<?> getSalt(@RequestParam("email") String email) {
                if (email == null || email.isEmpty()) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
                }
                String normalizedEmail = email.toLowerCase().trim();
                return userRepository.findByEmail(normalizedEmail)
                                .map(user -> ResponseEntity.ok(Map.of("salt", user.getSalt())))
                                .orElseGet(() -> {
                                        // Constant fake salt derivation to prevent enumeration
                                        String fakeSalt = generateFakeSalt(normalizedEmail);
                                        return ResponseEntity.ok(Map.of("salt", fakeSalt));
                                });
        }

        private String generateFakeSalt(String email) {
                try {
                        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                        String pepper = "kypher-v1-shield-" + email;
                        byte[] hash = digest.digest(pepper.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        StringBuilder hexString = new StringBuilder();
                        for (int i = 0; i < 16; i++) {
                                String hex = Integer.toHexString(0xff & hash[i]);
                                if (hex.length() == 1)
                                        hexString.append('0');
                                hexString.append(hex);
                        }
                        return hexString.toString();
                } catch (Exception e) {
                        return "00000000000000000000000000000000";
                }
        }

        @PostMapping("/register")
        public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
                String normalizedEmail = signUpRequest.getEmail().toLowerCase().trim();

                // Production defaults to requiring a verification ticket. Local testing can
                // explicitly opt out through the ignored secrets.properties file.
                if (otpRequired && !otpService.isEmailVerified(normalizedEmail)) {
                        return ResponseEntity.status(403)
                                        .body(Map.of("message",
                                                        "Error: Email verification required before registration."));
                }

                String clientIp = request.getRemoteAddr();
                String rateLimitKey = "register_" + clientIp + "_" + normalizedEmail;

                if (!rateLimitService.resolveKeyBucket(rateLimitKey).tryConsume(1)) {
                        return ResponseEntity.status(429)
                                        .body(Map.of("message", "Too many registration attempts. Please wait."));
                }

                if (userRepository.existsByEmail(normalizedEmail)) {
                        return ResponseEntity.badRequest().body(Map.of("message", "Error: Email is already in use!"));
                }

                User user = User.builder()
                                .email(normalizedEmail)
                                .passwordHash(encoder.encode(signUpRequest.getPassword()))
                                .salt(signUpRequest.getSalt())
                                .publicKey(signUpRequest.getPublicKey())
                                .encryptedPrivateKey(signUpRequest.getEncryptedPrivateKey())
                                .build();

                userRepository.save(user);

                // Consume a verification ticket after successful production registration.
                if (otpRequired) {
                        otpService.consumeTicket(normalizedEmail);
                }

                return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
        }

        @PostMapping("/login")
        public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
                String clientIp = request.getRemoteAddr();
                String rateLimitKey = "login_" + clientIp + "_" + loginRequest.getEmail();

                if (!rateLimitService.resolveKeyBucket(rateLimitKey).tryConsume(1)) {
                        return ResponseEntity.status(429)
                                        .body(Map.of("message", "Too many login attempts. Please wait a minute."));
                }

                try {
                        Authentication authentication = authenticationManager.authenticate(
                                        new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
                                                        loginRequest.getPassword()));

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        String jwt = jwtUtils.generateJwtToken(authentication);

                        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();

                        return ResponseEntity.ok()
                                        .header(org.springframework.http.HttpHeaders.SET_COOKIE,
                                                        "jwt_token=" + jwt
                                                                        + "; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict")
                                        .body(new JwtResponse(jwt, user.getEmail(), user.getSalt(), user.getPublicKey(),
                                                        user.getEncryptedPrivateKey()));
                } catch (org.springframework.security.authentication.BadCredentialsException e) {
                        return ResponseEntity.status(401).body(Map.of("message", "Error: Invalid email or password"));
                } catch (Exception e) {
                        e.printStackTrace();
                        return ResponseEntity.status(500).body(Map.of("message", "Error: " + e.getMessage()));
                }
        }

        @PostMapping("/logout")
        public ResponseEntity<?> logoutUser() {
                String jwt = null;
                jakarta.servlet.http.Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                        for (jakarta.servlet.http.Cookie cookie : cookies) {
                                if ("jwt_token".equals(cookie.getName())) {
                                        jwt = cookie.getValue();
                                }
                        }
                }
                if (jwt == null) {
                        String headerAuth = request.getHeader("Authorization");
                        if (org.springframework.util.StringUtils.hasText(headerAuth)
                                        && headerAuth.startsWith("Bearer ")) {
                                jwt = headerAuth.substring(7);
                        }
                }

                if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                        try {
                                java.util.Date expiration = jwtUtils.getExpirationDateFromJwtToken(jwt);
                                tokenBlacklistService.blacklistToken(jwt, expiration);
                        } catch (Exception e) {
                        }
                }

                return ResponseEntity.ok()
                                .header(org.springframework.http.HttpHeaders.SET_COOKIE,
                                                "jwt_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Strict")
                                .body(Map.of("message", "You have been logged out."));
        }

        @PostMapping("/refresh")
        public ResponseEntity<?> refreshToken() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication == null || !authentication.isAuthenticated()
                                || authentication.getPrincipal().equals("anonymousUser")) {
                        return ResponseEntity.status(401).body(Map.of("message", "Error: Not authenticated"));
                }

                // SECURE ROTATION: Blacklist the old token immediately
                String oldJwt = null;
                jakarta.servlet.http.Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                        for (jakarta.servlet.http.Cookie cookie : cookies) {
                                if ("jwt_token".equals(cookie.getName())) {
                                        oldJwt = cookie.getValue();
                                }
                        }
                }
                if (oldJwt != null && jwtUtils.validateJwtToken(oldJwt)) {
                        try {
                                java.util.Date expiration = jwtUtils.getExpirationDateFromJwtToken(oldJwt);
                                tokenBlacklistService.blacklistToken(oldJwt, expiration);
                        } catch (Exception e) {
                        }
                }

                String jwt = jwtUtils.generateJwtToken(authentication);
                String email = authentication.getName();
                User user = userRepository.findByEmail(email).orElseThrow();

                return ResponseEntity.ok()
                                .header(org.springframework.http.HttpHeaders.SET_COOKIE,
                                                "jwt_token=" + jwt
                                                                + "; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict")
                                .body(new JwtResponse(jwt, user.getEmail(), user.getSalt(), user.getPublicKey(),
                                                user.getEncryptedPrivateKey()));
        }

        @PutMapping("/identity")
        public ResponseEntity<?> updateIdentity(@RequestBody java.util.Map<String, String> requestBody) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication == null || !authentication.isAuthenticated()
                                || authentication.getPrincipal().equals("anonymousUser")) {
                        return ResponseEntity.status(401).body(java.util.Map.of("message", "Error: Not authenticated"));
                }

                String email = authentication.getName();
                User user = userRepository.findByEmail(email).orElseThrow();

                if (user.getPublicKey() != null) {
                        return ResponseEntity.badRequest()
                                        .body(java.util.Map.of("message", "Error: Identity already exists!"));
                }

                user.setPublicKey(requestBody.get("publicKey"));
                user.setEncryptedPrivateKey(requestBody.get("encryptedPrivateKey"));
                userRepository.save(user);

                return ResponseEntity.ok(java.util.Map.of("message", "Identity updated successfully!"));
        }
}
