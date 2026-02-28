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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
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

    private User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
    }

    /**
     * Verifies if a user has access to a project.
     * Proactively creates a membership record if the user is the owner but no
     * record exists.
     */
    private ProjectMember ensureMembership(Project project, User user) {
        // 1. Direct match (High performance)
        Optional<ProjectMember> existing = projectMemberRepository.findByProjectAndUser(project, user);
        if (existing.isPresent()) {
            return existing.get();
        }

        // 2. Email fallback (Handles casing issues in user records)
        List<ProjectMember> allMembers = projectMemberRepository.findByProject(project);
        for (ProjectMember pm : allMembers) {
            if (pm.getUser().getEmail().equalsIgnoreCase(user.getEmail())) {
                return pm;
            }
        }

        // 3. Ownership bridge (Handles legacy projects where owner isn't in members
        // list)
        if (project.getUser() != null) {
            User owner = project.getUser();
            if (owner.getId().equals(user.getId()) || owner.getEmail().equalsIgnoreCase(user.getEmail())) {
                logger.info("Migrating owner {} to member list for project {}", user.getEmail(), project.getName());
                ProjectMember member = ProjectMember.builder()
                        .project(project)
                        .user(user)
                        .role("OWNER")
                        .build();
                return projectMemberRepository.saveAndFlush(member);
            }
        }

        return null;
    }

    @GetMapping("/projects")
    public List<ProjectDTO> getProjects() {
        User user = getCurrentUser();

        // High-reliability backfill for owners
        List<Project> ownedProjects = projectRepository.findByUser(user);
        for (Project p : ownedProjects) {
            ensureMembership(p, user);
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
        ensureMembership(saved, user);

        dto.setId(saved.getId());
        return ResponseEntity.ok(dto);
    }

    @PutMapping("/projects/{id}")
    public ResponseEntity<ProjectDTO> updateProject(@PathVariable UUID id, @RequestBody ProjectDTO dto) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        if (ensureMembership(project, currentUser) == null) {
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

        if (!project.getUser().getId().equals(currentUser.getId())) {
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message", "Only the project owner can delete the project"));
        }

        projectRepository.delete(project);
        return ResponseEntity.ok().build();
    }

    // --- Key Management Methods (Moved from ApiKeyController) ---

    @GetMapping("/projects/{projectId}/keys")
    public ResponseEntity<List<ApiKeyDTO>> getKeysByProject(@PathVariable UUID projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        User currentUser = getCurrentUser();

        if (ensureMembership(project, currentUser) == null) {
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

        if (ensureMembership(project, currentUser) == null) {
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

        if (ensureMembership(key.getProject(), currentUser) == null) {
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

        if (ensureMembership(key.getProject(), currentUser) == null) {
            return ResponseEntity.status(403).build();
        }

        apiKeyRepository.delete(key);
        return ResponseEntity.ok().build();
    }

    // --- Member Management Methods ---

    @GetMapping("/projects/{id}/members")
    public ResponseEntity<List<java.util.Map<String, String>>> getMembers(@PathVariable UUID id) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        ProjectMember pm = ensureMembership(project, currentUser);
        if (pm == null) {
            return ResponseEntity.status(403).body(java.util.List
                    .of(java.util.Map.of("error", "Access Denied: You are not a member of this project.")));
        }

        List<java.util.Map<String, String>> membersList = projectMemberRepository.findByProject(project).stream()
                .map(m -> {
                    java.util.Map<String, String> mData = new java.util.HashMap<>();
                    mData.put("email", m.getUser().getEmail());
                    mData.put("role", m.getRole());
                    return mData;
                }).collect(Collectors.toList());

        return ResponseEntity.ok(membersList);
    }

    @PostMapping("/projects/{id}/members")
    public ResponseEntity<?> addMember(@PathVariable UUID id, @RequestBody java.util.Map<String, String> body) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        ProjectMember pm = ensureMembership(project, currentUser);
        if (pm == null || !"OWNER".equalsIgnoreCase(pm.getRole())) {
            return ResponseEntity.status(403).body(
                    java.util.Map.of("message", "Access Denied: Only project owners can manage members."));
        }

        String email = body.get("email").toLowerCase();
        User userToAdd = userRepository.findByEmail(email).orElse(null);
        if (userToAdd == null) {
            return ResponseEntity.badRequest()
                    .body(java.util.Map.of("message", "User with email '" + email + "' not found"));
        }

        if (projectMemberRepository.findByProjectAndUser(project, userToAdd).isPresent()) {
            return ResponseEntity.badRequest().body(java.util.Map.of("message", "User is already a member"));
        }

        ProjectMember newMember = ProjectMember.builder()
                .project(project)
                .user(userToAdd)
                .role("MEMBER")
                .build();
        projectMemberRepository.save(newMember);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/projects/{id}/members/remove")
    public ResponseEntity<?> removeMember(@PathVariable UUID id, @RequestBody java.util.Map<String, String> body) {
        String email = body.get("email");
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        ProjectMember pm = ensureMembership(project, currentUser);
        if (pm == null || !"OWNER".equalsIgnoreCase(pm.getRole())) {
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message", "Access Denied: Only project owners can remove members."));
        }

        List<ProjectMember> allMembers = projectMemberRepository.findByProject(project);
        ProjectMember memberToRemove = allMembers.stream()
                .filter(m -> m.getUser().getEmail().equalsIgnoreCase(email))
                .findFirst()
                .orElse(null);

        if (memberToRemove == null) {
            return ResponseEntity.badRequest()
                    .body(java.util.Map.of("message", "User is not a member of this project."));
        }

        // Prevent owner from removing themselves
        if (memberToRemove.getUser().getId().equals(project.getUser().getId())) {
            return ResponseEntity.badRequest()
                    .body(java.util.Map.of("message", "The project owner cannot be removed."));
        }

        projectMemberRepository.delete(memberToRemove);
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
