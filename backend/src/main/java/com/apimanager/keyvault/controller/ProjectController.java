package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.ProjectDTO;
import org.springframework.cache.annotation.Cacheable;
import com.apimanager.keyvault.dto.ProjectSummaryDTO;
import com.apimanager.keyvault.dto.ApiKeyDTO;
import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.model.ProjectMember;
import com.apimanager.keyvault.repository.ProjectRepository;
import com.apimanager.keyvault.repository.UserRepository;
import com.apimanager.keyvault.repository.ApiKeyRepository;
import com.apimanager.keyvault.dto.MachineTokenDTO;
import com.apimanager.keyvault.dto.MachineTokenRequest;
import com.apimanager.keyvault.model.MachineToken;
import com.apimanager.keyvault.repository.MachineTokenRepository;
import com.apimanager.keyvault.model.ApiKeyVersion;
import com.apimanager.keyvault.repository.ApiKeyVersionRepository;
import com.apimanager.keyvault.repository.ProjectMemberRepository;
import com.apimanager.keyvault.service.TeamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.validation.Valid;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@Transactional
public class ProjectController {

    @Autowired
    private com.apimanager.keyvault.service.RateLimitService rateLimitService;

    @Autowired
    private jakarta.servlet.http.HttpServletRequest request;

    private static final Logger logger = LoggerFactory.getLogger(ProjectController.class);

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProjectMemberRepository projectMemberRepository;

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private TeamService teamService;

    @Autowired
    private com.apimanager.keyvault.service.AuditService auditService;

    @Autowired
    private ApiKeyVersionRepository apiKeyVersionRepository;

    @Autowired
    private com.apimanager.keyvault.repository.AuditLogRepository auditLogRepository;

    @Autowired
    private MachineTokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
    }

    @GetMapping("/projects")
    public List<ProjectDTO> getProjects() {
        User user = getCurrentUser();
        java.time.LocalDate today = java.time.LocalDate.now();
        java.time.LocalDate nextWeek = today.plusDays(7);

        // Professional Solution: Use high-performance Aggregated Summary query
        // to prevent N+1 performance degradation. One query for everything.
        List<ProjectSummaryDTO> summaries = projectRepository.getProjectSummaries(user, today, nextWeek);
        return summaries.stream()
                .map(summary -> {
                    ProjectDTO dto = new ProjectDTO();
                    dto.setId(summary.getId());
                    dto.setName(summary.getName());
                    dto.setTag(summary.getTag());
                    dto.setOwnerEmail(summary.getOwnerEmail());
                    dto.setEncryptedProjectKey(summary.getEncryptedProjectKey());
                    dto.setKeyCount(summary.getKeyCount());
                    dto.setExpiringKeyCount(summary.getExpiringKeyCount());
                    return dto;
                }).collect(Collectors.toList());
    }

    /**
     * Optimized Notification Discovery:
     * Provides a lightweight telemetry endpoint that returns the global
     * security risk state (expiring key count) across all contexts.
     * 
     * Uses Server-Side Caching:
     * Results are cached for 5 minutes per user to prevent DB spikes
     * from high-frequency frontend polling or multi-tab usage.
     */
    @GetMapping("/notifications/summary")
    @Cacheable(value = "notification_summary", key = "#root.target.getCurrentUser().email")
    public java.util.Map<String, Object> getNotificationSummary() {
        User user = getCurrentUser();
        java.time.LocalDate today = java.time.LocalDate.now();
        java.time.LocalDate nextWeek = today.plusDays(7);

        long expiringCount = apiKeyRepository.countExpiringKeysForUser(user, today, nextWeek);

        return java.util.Map.of(
                "expiringCount", expiringCount,
                "periodDays", 7,
                "timestamp", java.time.Instant.now().toString());
    }

    @PostMapping("/projects")
    public ResponseEntity<?> createProject(@Valid @RequestBody ProjectDTO dto) {
        User user = getCurrentUser();

        // Resource Protection: Limit creation rate to prevent spam/DoS
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "project_mutation_" + clientIp + "_" + user.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        Project project = Project.builder()
                .name(dto.getName())
                .tag(dto.getTag())
                .user(user)
                .build();
        Project saved = projectRepository.save(project);

        // Add creator as owner in member list
        ProjectMember ownerMember = teamService.ensureMembership(saved, user);
        if (dto.getEncryptedProjectKey() != null) {
            ownerMember.setEncryptedProjectKey(dto.getEncryptedProjectKey());
            projectMemberRepository.save(ownerMember);
        }

        auditService.logAction(saved, user, "CREATE_PROJECT", "PROJECT", saved.getId().toString(),
                "Created project " + saved.getName());

        dto.setId(saved.getId());
        dto.setOwnerEmail(user.getEmail());
        return ResponseEntity.ok(dto);
    }

    @PutMapping("/projects/{id}")
    public ResponseEntity<?> updateProject(@PathVariable("id") UUID id, @Valid @RequestBody ProjectDTO dto) {
        Project project = projectRepository.findByIdWithUser(id)
                .orElseThrow(() -> new RuntimeException("Context not found in secure registry."));
        User currentUser = getCurrentUser();

        // Resource Protection
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "project_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        try {
            teamService.verifyRole(project, currentUser, "OWNER");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
        }

        project.setName(dto.getName());
        project.setTag(dto.getTag());
        projectRepository.save(project);

        auditService.logAction(project, currentUser, "UPDATE_PROJECT", "PROJECT", project.getId().toString(),
                "Updated project details");

        return ResponseEntity.ok(dto);
    }

    @DeleteMapping("/projects/{id}")
    @Transactional
    public ResponseEntity<?> deleteProject(@PathVariable("id") UUID id) {
        Project project = projectRepository.findByIdWithUser(id)
                .orElseThrow(() -> new RuntimeException("Project not found"));
        User currentUser = getCurrentUser();

        // Resource Protection
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "project_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        logger.info("User {} attempting to delete project {} (ID: {})",
                currentUser.getEmail(), project.getName(), id);

        // 1. Ownership check (Robust ID + Email fallback)
        boolean isDirectOwner = project.getUser() != null
                && project.getUser().getId().equals(currentUser.getId());

        if (!isDirectOwner) {
            String uEmail = currentUser.getEmail().toLowerCase().trim();
            String oEmail = project.getUser() != null ? project.getUser().getEmail().toLowerCase().trim() : "";
            if (!uEmail.equals(oEmail) || uEmail.isEmpty()) {
                try {
                    teamService.verifyRole(project, currentUser, "OWNER");
                } catch (RuntimeException e) {
                    logger.warn("Access Denied: User {} is not owner of project {}",
                            currentUser.getEmail(), project.getName());
                    return ResponseEntity.status(403)
                            .body(java.util.Map.of("message",
                                    "Access Denied: Only the project owner can delete this workspace."));
                }
            }
        }

        try {
            // 2. Delete Non-Cascading Dependencies
            // Audit logs contain binary association with Project
            auditLogRepository.deleteByProject(project);

            // Machine Tokens are not currently in the Project entity's cascade list
            tokenRepository.deleteByProject(project);

            // 3. Delete Project record (triggers cascade ALL for members/keys)
            projectRepository.delete(project);

            logger.info("Successfully purged project: {} (ID: {})", project.getName(), id);
            return ResponseEntity
                    .ok(java.util.Map.of("message", "Project and all associated data purged successfully."));
        } catch (Exception e) {
            logger.error("Internal failure during project deletion for {}: {}", id, e.getMessage());
            return ResponseEntity.status(500)
                    .body(java.util.Map.of("message", "Database Constraint Violation: " + e.getMessage()));
        }
    }

    // --- Key Management Methods ---

    @GetMapping("/projects/{projectId}/keys")
    public ResponseEntity<?> getKeysByProject(@PathVariable("projectId") UUID projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.verifyRole(project, currentUser, "VIEWER");
        } catch (Exception e) {
            // Fallback: allow project owner access even if role verification fails
            User owner = project.getUser();
            if (owner != null && owner.getId().equals(currentUser.getId())) {
                logger.debug("Owner access granted for project {} to user {} via ID fallback.", project.getId(),
                        currentUser.getEmail());
            } else {
                logger.warn("Access denied for user {} to keys of project {}: {}", currentUser.getEmail(),
                        project.getName(), e.getMessage());
                return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
            }
        }

        auditService.logAction(project, currentUser, "VIEW_KEYS", "PROJECT", project.getId().toString(),
                "Viewed API Keys list");

        List<ApiKeyDTO> keys = apiKeyRepository.findByProject(project).stream().map(this::convertToApiKeyDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(keys);
    }

    @PostMapping("/keys")
    public ResponseEntity<?> createKey(@Valid @RequestBody ApiKeyDTO dto) {
        Project project = projectRepository.findByIdWithUser(dto.getProjectId())
                .orElseThrow(() -> new RuntimeException("Target context not found."));
        User currentUser = getCurrentUser();

        // Critical Protection: Secret creation involves heavy client/server crypto sync
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "key_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        try {
            teamService.verifyRole(project, currentUser, "EDITOR");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        ApiKey key = ApiKey.builder()
                .name(dto.getName())
                .service(dto.getService())
                .environment(dto.getEnvironment())
                .encryptedValue(dto.getEncryptedValue())
                .iv(dto.getIv())
                .expiryDate(dto.getExpiryDate())
                .notes(dto.getNotes())
                .project(project)
                .build();

        ApiKey saved = apiKeyRepository.save(key);

        // Version 1
        apiKeyVersionRepository.saveAndFlush(ApiKeyVersion.builder()
                .apiKey(saved)
                .version(saved.getCurrentVersion())
                .name(saved.getName())
                .service(saved.getService())
                .environment(saved.getEnvironment())
                .encryptedValue(saved.getEncryptedValue())
                .iv(saved.getIv())
                .expiryDate(saved.getExpiryDate())
                .notes(saved.getNotes())
                .updatedBy(currentUser.getEmail())
                .build());

        auditService.logAction(project, currentUser, "CREATE_KEY", "API_KEY", saved.getId().toString(),
                "Created key: " + saved.getName());
        return ResponseEntity.ok(convertToApiKeyDTO(saved));
    }

    @PutMapping("/keys/{id}")
    public ResponseEntity<?> updateKey(@PathVariable("id") UUID id, @Valid @RequestBody ApiKeyDTO dto) {
        ApiKey key = apiKeyRepository.findByIdWithProjectAndUser(id)
                .orElseThrow(() -> new RuntimeException("Secret identifier not found."));
        User currentUser = getCurrentUser();

        // Critical Protection
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "key_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        try {
            teamService.verifyRole(key.getProject(), currentUser, "EDITOR");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
        }

        key.setName(dto.getName());
        key.setService(dto.getService());
        key.setEnvironment(dto.getEnvironment());
        key.setEncryptedValue(dto.getEncryptedValue());
        key.setIv(dto.getIv());
        key.setExpiryDate(dto.getExpiryDate());
        key.setNotes(dto.getNotes());
        key.setCurrentVersion(key.getCurrentVersion() + 1);

        apiKeyRepository.saveAndFlush(key);

        ApiKeyVersion versionRecord = ApiKeyVersion.builder()
                .apiKey(key)
                .version(key.getCurrentVersion())
                .name(key.getName())
                .service(key.getService())
                .environment(key.getEnvironment())
                .encryptedValue(key.getEncryptedValue())
                .iv(key.getIv())
                .expiryDate(key.getExpiryDate())
                .notes(key.getNotes())
                .updatedBy(currentUser.getEmail())
                .build();

        apiKeyVersionRepository.saveAndFlush(versionRecord);

        System.out.println(
                "[Vault] Updated key " + key.getId() + " to v" + key.getCurrentVersion() + ". Snapshot saved.");

        auditService.logAction(key.getProject(), currentUser, "UPDATE_KEY", "API_KEY", key.getId().toString(),
                "Updated key: " + key.getName() + " (v" + key.getCurrentVersion() + ")");
        return ResponseEntity.ok(convertToApiKeyDTO(key));
    }

    @GetMapping("/keys/{id}/history")
    public ResponseEntity<List<java.util.Map<String, Object>>> getKeyHistory(@PathVariable("id") UUID id) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.verifyRole(key.getProject(), currentUser, "VIEWER");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        List<java.util.Map<String, Object>> history = apiKeyVersionRepository.findByApiKeyOrderByVersionDesc(key)
                .stream().map(v -> {
                    java.util.Map<String, Object> map = new java.util.HashMap<>();
                    map.put("version", v.getVersion());
                    map.put("createdAt", v.getCreatedAt());
                    map.put("updatedBy", v.getUpdatedBy());
                    map.put("notes", v.getNotes());
                    map.put("name", v.getName());
                    map.put("service", v.getService());
                    return map;
                }).collect(Collectors.toList());

        return ResponseEntity.ok(history);
    }

    @Transactional
    @PostMapping("/keys/{id}/rollback/{versionId}")
    public ResponseEntity<?> rollbackKey(@PathVariable("id") UUID id,
            @PathVariable("versionId") Integer version) {
        ApiKey key = apiKeyRepository.findByIdWithProjectAndUser(id)
                .orElseThrow(() -> new RuntimeException("Secret timeline entry not found."));
        User currentUser = getCurrentUser();

        // Critical Protection: Rollbacks involve heavy snapshot transitions
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "key_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many requests. Please wait a minute."));
        }

        try {
            teamService.verifyRole(key.getProject(), currentUser, "EDITOR");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
        }

        List<ApiKeyVersion> history = apiKeyVersionRepository.findByApiKeyOrderByVersionDesc(key);
        logger.info("[Vault] Rollback initiated for Key: {} (ID: {}). History depth: {}", key.getName(), id,
                history.size());

        ApiKeyVersion target = history.stream()
                .filter(v -> Integer.valueOf(v.getVersion()).equals(version))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "Version " + version + " not found in history snapshot of " + history.size() + " records."));

        logger.info("[Vault] Rollback target v{} selected.", target.getVersion());

        key.setName(target.getName());
        key.setService(target.getService());
        key.setEnvironment(target.getEnvironment());
        key.setEncryptedValue(target.getEncryptedValue());
        key.setIv(target.getIv());
        key.setExpiryDate(target.getExpiryDate());
        key.setNotes(target.getNotes());

        int nextVersion = key.getCurrentVersion() + 1;
        key.setCurrentVersion(nextVersion);

        ApiKey restored = apiKeyRepository.saveAndFlush(key);

        apiKeyVersionRepository.saveAndFlush(ApiKeyVersion.builder()
                .apiKey(restored)
                .version(nextVersion)
                .name(restored.getName())
                .service(restored.getService())
                .environment(restored.getEnvironment())
                .encryptedValue(restored.getEncryptedValue())
                .iv(restored.getIv())
                .expiryDate(restored.getExpiryDate())
                .notes(restored.getNotes())
                .updatedBy(currentUser.getEmail() + " (Rollback to v" + version + ")")
                .build());

        logger.info("[Vault] Rollback successful. New version created: v{}", nextVersion);

        auditService.logAction(restored.getProject(), currentUser, "ROLLBACK_KEY", "API_KEY",
                restored.getId().toString(),
                "Rolled back key: " + restored.getName() + " to v" + version);

        return ResponseEntity.ok(convertToApiKeyDTO(restored));
    }

    @DeleteMapping("/keys/{id}")
    public ResponseEntity<?> deleteKey(@PathVariable("id") UUID id) {
        ApiKey key = apiKeyRepository.findByIdWithProjectAndUser(id)
                .orElseThrow(() -> new RuntimeException("Secret not found."));
        User currentUser = getCurrentUser();

        // Resource Protection
        String clientIp = request.getRemoteAddr();
        String rateLimitKey = "key_mutation_" + clientIp + "_" + currentUser.getEmail();
        if (!rateLimitService.resolveBucket(rateLimitKey, 10, 10, Duration.ofMinutes(1)).tryConsume(1)) {
            return ResponseEntity.status(429).body(java.util.Map.of("message", "Too many requests."));
        }

        try {
            teamService.verifyRole(key.getProject(), currentUser, "EDITOR");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        auditService.logAction(key.getProject(), currentUser, "DELETE_KEY", "API_KEY", key.getId().toString(),
                "Deleted key: " + key.getName());
        apiKeyRepository.delete(key);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/projects/{projectId}/audit-logs")
    public ResponseEntity<?> getAuditLogs(@PathVariable("projectId") UUID projectId,
            @RequestParam(value = "days", defaultValue = "30") Integer days) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.verifyRole(project, currentUser, "ADMIN");
        } catch (Exception e) {
            // Allow owner access as fallback
            User owner = project.getUser();
            if (owner != null && owner.getId().equals(currentUser.getId())) {
                logger.debug("Owner access granted for audit logs of project {} to user {} via ID fallback.",
                        project.getId(), currentUser.getEmail());
            } else {
                logger.warn("Access denied for user {} to audit logs of project {}: {}", currentUser.getEmail(),
                        project.getName(), e.getMessage());
                return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
            }
        }

        // Professional Guard: Prevent DB burst by limiting the time window.
        // Default is 30 days, but configurable via UI.
        LocalDateTime threshold = LocalDateTime.now().minusDays(days);

        List<com.apimanager.keyvault.model.AuditLog> logs = auditLogRepository
                .findByProjectAndCreatedAtAfterOrderByCreatedAtDesc(project, threshold);

        List<com.apimanager.keyvault.dto.AuditLogDTO> dtos = logs.stream().map(l -> {
            com.apimanager.keyvault.dto.AuditLogDTO d = new com.apimanager.keyvault.dto.AuditLogDTO();
            d.setId(l.getId());
            d.setProjectId(l.getProject().getId());
            d.setUserEmail(l.getUser().getEmail());
            d.setAction(l.getAction());
            d.setTargetType(l.getTargetType());
            d.setTargetId(l.getTargetId());
            d.setDetails(l.getDetails());
            d.setIpAddress(l.getIpAddress());
            d.setCreatedAt(l.getCreatedAt());
            return d;
        }).collect(Collectors.toList());
        return ResponseEntity.ok(dtos);
    }

    private ApiKeyDTO convertToApiKeyDTO(ApiKey key) {
        ApiKeyDTO dto = new ApiKeyDTO();
        dto.setId(key.getId());
        dto.setProjectId(key.getProject().getId());
        dto.setName(key.getName());
        dto.setService(key.getService());
        dto.setEnvironment(key.getEnvironment());
        dto.setEncryptedValue(key.getEncryptedValue());
        dto.setIv(key.getIv());
        dto.setExpiryDate(key.getExpiryDate());
        dto.setNotes(key.getNotes());
        dto.setVersion(key.getCurrentVersion());
        return dto;
    }

    // --- Machine Token Management ---

    @GetMapping("/projects/{projectId}/tokens")
    public ResponseEntity<?> getProjectTokens(@PathVariable("projectId") UUID projectId) {
        logger.info("Fetching machine tokens for project: {}", projectId);
        try {
            teamService.ensureMembership(projectId);
            List<MachineToken> tokens = tokenRepository.findByProject_Id(projectId);
            return ResponseEntity.ok(tokens.stream().map(t -> MachineTokenDTO.builder()
                    .id(t.getId())
                    .name(t.getName())
                    .tokenId(t.getTokenId())
                    .createdAt(t.getCreatedAt())
                    .build()).collect(Collectors.toList()));
        } catch (RuntimeException e) {
            logger.error("Error fetching tokens: {}", e.getMessage());
            return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/projects/{projectId}/tokens")
    public ResponseEntity<?> createMachineToken(@PathVariable("projectId") UUID projectId,
            @RequestBody MachineTokenRequest request) {
        logger.info("Creating machine token for project: {}", projectId);
        try {
            teamService.ensureAdmin(projectId);
            Project project = projectRepository.findById(projectId)
                    .orElseThrow(() -> new RuntimeException("Project not found"));

            MachineToken token = MachineToken.builder()
                    .project(project)
                    .name(request.getName())
                    .tokenId(request.getTokenId())
                    .tokenHash(passwordEncoder.encode(request.getTokenHash()))
                    .encryptedProjectKey(request.getEncryptedProjectKey())
                    .build();

            tokenRepository.save(token);
            auditService.logAction(project, getCurrentUser(), "CREATE_TOKEN", "MACHINE_TOKEN", token.getId().toString(),
                    "Generated new machine identity: " + request.getName());
            return ResponseEntity.ok(java.util.Map.of("message", "Machine Token registered successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(java.util.Map.of("message", e.getMessage()));
        }
    }

    @DeleteMapping("/tokens/{tokenId}")
    public ResponseEntity<?> revokeMachineToken(@PathVariable("tokenId") UUID tokenId) {
        try {
            MachineToken token = tokenRepository.findById(tokenId)
                    .orElseThrow(() -> new RuntimeException("Token not found"));
            Project project = token.getProject();
            teamService.ensureAdmin(project.getId());

            tokenRepository.delete(token);
            auditService.logAction(project, getCurrentUser(), "REVOKE_TOKEN", "MACHINE_TOKEN", tokenId.toString(),
                    "Revoked machine identity: " + token.getName());
            return ResponseEntity.ok(java.util.Map.of("message", "Token revoked successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(java.util.Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/tokens/verify")
    public ResponseEntity<?> verifyMachineToken(@RequestBody java.util.Map<String, String> verifyRequest) {
        String clientIp = request.getRemoteAddr();
        String tokenId = verifyRequest.get("tokenId");
        String rateLimitKey = "verify_" + clientIp + "_" + tokenId;

        if (!rateLimitService.resolveKeyBucket(rateLimitKey).tryConsume(1)) {
            return ResponseEntity.status(429)
                    .body(java.util.Map.of("message", "Too many verification attempts. Please wait a minute."));
        }

        String incomingHash = verifyRequest.get("tokenHash");

        MachineToken token = tokenRepository.findByTokenId(tokenId)
                .orElseThrow(() -> new RuntimeException("Invalid Machine Token ID"));

        boolean matches = false;
        String storedHash = token.getTokenHash();

        if (storedHash != null && storedHash.startsWith("$2a$")) {
            matches = passwordEncoder.matches(incomingHash, storedHash);
        } else {
            // Legacy Migration Shield: Deep check for existing SHA-256 tokens
            matches = storedHash != null && storedHash.equals(incomingHash);
            if (matches) {
                // Transparently upgrade the token to secure BCrypt format on the fly
                token.setTokenHash(passwordEncoder.encode(incomingHash));
                tokenRepository.save(token);
                logger.info("Successfully migrated machine identity {} to modern security standards.", tokenId);
            }
        }

        if (!matches) {
            return ResponseEntity.status(401).body(java.util.Map.of("message", "Invalid Token Secret"));
        }

        String requestedEnv = verifyRequest.get("environment");
        List<ApiKeyDTO> keys = apiKeyRepository.findByProject(token.getProject()).stream()
                .filter(k -> requestedEnv == null || requestedEnv.equalsIgnoreCase(k.getEnvironment()))
                .map(this::convertToApiKeyDTO)
                .collect(Collectors.toList());

        logger.info("[Security] Machine Token verified for project: {} (Env: {})",
                token.getProject().getName(), requestedEnv != null ? requestedEnv : "ALL");

        return ResponseEntity.ok(java.util.Map.of(
                "projectId", token.getProject().getId(),
                "projectName", token.getProject().getName(),
                "projectTag", token.getProject().getTag() != null ? token.getProject().getTag() : "no-tag",
                "encryptedProjectKey", token.getEncryptedProjectKey(),
                "keys", keys));
    }
}
