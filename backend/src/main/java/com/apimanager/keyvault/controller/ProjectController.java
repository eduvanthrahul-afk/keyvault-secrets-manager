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

        dto.setId(saved.getId());
        return ResponseEntity.ok(dto);
    }

    @PutMapping("/projects/{id}")
    public ResponseEntity<ProjectDTO> updateProject(@PathVariable UUID id, @RequestBody ProjectDTO dto) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            ProjectMember member = teamService.ensureMembership(project, currentUser);
            if (!"OWNER".equalsIgnoreCase(member.getRole())) {
                return ResponseEntity.status(403).build();
            }
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        project.setName(dto.getName());
        project.setTag(dto.getTag());
        projectRepository.save(project);
        return ResponseEntity.ok(dto);
    }

    @DeleteMapping("/projects/{id}")
    public ResponseEntity<?> deleteProject(@PathVariable UUID id) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            ProjectMember member = teamService.ensureMembership(project, currentUser);
            if (!"OWNER".equalsIgnoreCase(member.getRole())) {
                return ResponseEntity.status(403)
                        .body(java.util.Map.of("message", "Only project owners can delete the project."));
            }
        } catch (RuntimeException e) {
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message", "Access Denied: You are not a member of this project."));
        }

        projectRepository.delete(project);
        return ResponseEntity.ok().build();
    }

    // --- Key Management Methods ---

    @GetMapping("/projects/{projectId}/keys")
    public ResponseEntity<List<ApiKeyDTO>> getKeysByProject(@PathVariable UUID projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.ensureMembership(project, currentUser);
        } catch (RuntimeException e) {
            logger.warn("Access denied for user {} to keys of project {}", currentUser.getEmail(), project.getName());
            return ResponseEntity.status(403).build();
        }

        List<ApiKeyDTO> keys = apiKeyRepository.findByProject(project).stream().map(this::convertToApiKeyDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(keys);
    }

    @PostMapping("/keys")
    public ResponseEntity<ApiKeyDTO> createKey(@RequestBody ApiKeyDTO dto) {
        Project project = projectRepository.findById(dto.getProjectId()).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.ensureMembership(project, currentUser);
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
        return ResponseEntity.ok(convertToApiKeyDTO(saved));
    }

    @PutMapping("/keys/{id}")
    public ResponseEntity<ApiKeyDTO> updateKey(@PathVariable UUID id, @RequestBody ApiKeyDTO dto) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.ensureMembership(key.getProject(), currentUser);
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
        return ResponseEntity.ok(convertToApiKeyDTO(key));
    }

    @DeleteMapping("/keys/{id}")
    public ResponseEntity<?> deleteKey(@PathVariable UUID id) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        try {
            teamService.ensureMembership(key.getProject(), currentUser);
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }

        apiKeyRepository.delete(key);
        return ResponseEntity.ok().build();
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
