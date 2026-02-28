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
        teamService.ensureMembership(saved, user);

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

        try {
            teamService.verifyRole(project, currentUser, "OWNER");
        } catch (RuntimeException e) {
            logger.warn("Access Denied for user {} attempting to delete project {} (ID: {}). Owner is {}. Error: {}",
                    currentUser.getEmail(), project.getName(), project.getId(),
                    (project.getUser() != null ? project.getUser().getEmail() : "NULL"), e.getMessage());
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message", e.getMessage()));
        }

        auditService.logAction(project, currentUser, "DELETE_PROJECT", "PROJECT", project.getId().toString(),
                "Deleted project");
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
}
