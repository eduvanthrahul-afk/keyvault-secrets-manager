package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.ProjectDTO;
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
import com.apimanager.keyvault.repository.ProjectMemberRepository;
import com.apimanager.keyvault.service.TeamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@Transactional
public class ProjectController {

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
    private com.apimanager.keyvault.repository.AuditLogRepository auditLogRepository;

    @Autowired
    private MachineTokenRepository tokenRepository;

    private User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
    }

    @GetMapping("/projects")
    public List<ProjectDTO> getProjects() {
        User user = getCurrentUser();

        // High-reliability backfill for owners via service
        List<Project> ownedProjects = projectRepository.findByUser(user);
        for (Project p : ownedProjects) {
            teamService.ensureMembership(p, user);
        }

        List<ProjectMember> memberships = projectMemberRepository.findByUser(user);
        return memberships.stream().map(pm -> {
            Project p = pm.getProject();
            ProjectDTO dto = new ProjectDTO();
            dto.setId(p.getId());
            dto.setName(p.getName());
            dto.setTag(p.getTag());
            // Add owner email for frontend permission handling
            if (p.getUser() != null) {
                dto.setOwnerEmail(p.getUser().getEmail());
            }
            if (pm.getEncryptedProjectKey() != null) {
                dto.setEncryptedProjectKey(pm.getEncryptedProjectKey());
            }
            return dto;
        }).collect(Collectors.toList());
    }

    @PostMapping("/projects")
    public ResponseEntity<ProjectDTO> createProject(@RequestBody ProjectDTO dto) {
        User user = getCurrentUser();
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
    public ResponseEntity<ProjectDTO> updateProject(@PathVariable("id") UUID id, @RequestBody ProjectDTO dto) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.verifyRole(project, currentUser, "OWNER");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        project.setName(dto.getName());
        project.setTag(dto.getTag());
        projectRepository.save(project);

        auditService.logAction(project, currentUser, "UPDATE_PROJECT", "PROJECT", project.getId().toString(),
                "Updated project details");

        return ResponseEntity.ok(dto);
    }

    @DeleteMapping("/projects/{id}")
    public ResponseEntity<?> deleteProject(@PathVariable("id") UUID id) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        // Primary check: direct ID-based ownership comparison to avoid lazy-proxy
        // issues that can cause verifyRole to misfire during a delete transaction.
        boolean isDirectOwner = project.getUser() != null
                && project.getUser().getId().equals(currentUser.getId());

        if (!isDirectOwner) {
            // Fallback: check via membership table (handles team OWNER role grants)
            try {
                teamService.verifyRole(project, currentUser, "OWNER");
            } catch (RuntimeException e) {
                logger.warn(
                        "Access Denied for user {} attempting to delete project {} (ID: {}). Owner is {}. Error: {}",
                        currentUser.getEmail(), project.getName(), project.getId(),
                        (project.getUser() != null ? project.getUser().getEmail() : "NULL"), e.getMessage());
                return ResponseEntity.status(403)
                        .body(java.util.Map.of("message",
                                "Access Denied: Only the project owner can delete this workspace."));
            }
        }

        // Delete audit logs first to avoid FK constraint violation
        // (audit_logs.project_id)
        // since Project has no cascade relationship to AuditLog.
        auditLogRepository.deleteByProject(project);

        projectRepository.delete(project);
        return ResponseEntity.ok().build();
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
    public ResponseEntity<ApiKeyDTO> createKey(@RequestBody ApiKeyDTO dto) {
        Project project = projectRepository.findById(dto.getProjectId()).orElseThrow();
        User currentUser = getCurrentUser();

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
        auditService.logAction(project, currentUser, "CREATE_KEY", "API_KEY", saved.getId().toString(),
                "Created key: " + saved.getName());
        return ResponseEntity.ok(convertToApiKeyDTO(saved));
    }

    @PutMapping("/keys/{id}")
    public ResponseEntity<ApiKeyDTO> updateKey(@PathVariable("id") UUID id, @RequestBody ApiKeyDTO dto) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.verifyRole(key.getProject(), currentUser, "EDITOR");
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        key.setName(dto.getName());
        key.setService(dto.getService());
        key.setEnvironment(dto.getEnvironment());
        key.setEncryptedValue(dto.getEncryptedValue());
        key.setIv(dto.getIv());
        key.setExpiryDate(dto.getExpiryDate());
        key.setNotes(dto.getNotes());

        apiKeyRepository.save(key);
        auditService.logAction(key.getProject(), currentUser, "UPDATE_KEY", "API_KEY", key.getId().toString(),
                "Updated key: " + key.getName());
        return ResponseEntity.ok(convertToApiKeyDTO(key));
    }

    @DeleteMapping("/keys/{id}")
    public ResponseEntity<?> deleteKey(@PathVariable("id") UUID id) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

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
    public ResponseEntity<?> getAuditLogs(@PathVariable("projectId") UUID projectId) {
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

        List<com.apimanager.keyvault.model.AuditLog> logs = auditLogRepository
                .findByProjectOrderByCreatedAtDesc(project);

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
                    .tokenHash(request.getTokenHash())
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
    public ResponseEntity<?> verifyMachineToken(@RequestBody java.util.Map<String, String> request) {
        String tokenId = request.get("tokenId");
        String tokenHash = request.get("tokenHash");

        MachineToken token = tokenRepository.findByTokenId(tokenId)
                .orElseThrow(() -> new RuntimeException("Invalid Machine Token ID"));

        if (!token.getTokenHash().equals(tokenHash)) {
            return ResponseEntity.status(401).body(java.util.Map.of("message", "Invalid Token Secret"));
        }

        return ResponseEntity.ok(java.util.Map.of(
                "projectId", token.getProject().getId(),
                "encryptedProjectKey", token.getEncryptedProjectKey()));
    }
}
