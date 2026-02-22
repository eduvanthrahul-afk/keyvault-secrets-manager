package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.ProjectDTO;
import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.ProjectRepository;
import com.apimanager.keyvault.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.transaction.annotation.Transactional;
import com.apimanager.keyvault.model.ProjectMember;

@RestController
@RequestMapping("/projects")
public class ProjectController {

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private com.apimanager.keyvault.repository.ProjectMemberRepository projectMemberRepository;

    private User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
    }

    private ProjectMember ensureMembership(Project project, User user) {
        // Try direct entity matching first
        Optional<ProjectMember> existing = projectMemberRepository.findByProjectAndUser(project, user);
        if (existing.isPresent()) {
            return existing.get();
        }

        // Fallback: Check all members for this project by email (case-insensitive)
        List<ProjectMember> allMembers = projectMemberRepository.findByProject(project);
        for (ProjectMember pm : allMembers) {
            if (pm.getUser().getEmail().equalsIgnoreCase(user.getEmail())) {
                return pm;
            }
        }

        // Migration Bridge: If currently logged in user is the project's recorded owner
        // (by email)
        if (project.getUser() != null && project.getUser().getEmail().equalsIgnoreCase(user.getEmail())) {
            ProjectMember member = ProjectMember.builder()
                    .project(project)
                    .user(user)
                    .role("OWNER")
                    .build();
            return projectMemberRepository.saveAndFlush(member);
        }

        return null;
    }

    @GetMapping
    @Transactional
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

    @PostMapping
    @Transactional
    public ResponseEntity<ProjectDTO> createProject(@RequestBody ProjectDTO dto) {
        User user = getCurrentUser();
        Project project = Project.builder()
                .name(dto.getName())
                .tag(dto.getTag())
                .user(user)
                .build();
        Project saved = projectRepository.save(project);

        // Add creator as member
        ensureMembership(saved, user);

        dto.setId(saved.getId());
        return ResponseEntity.ok(dto);
    }

    @PutMapping("/{id}")
    @Transactional
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

    @DeleteMapping("/{id}")
    @Transactional
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

    @PostMapping("/{id}/members")
    @Transactional
    public ResponseEntity<?> addMember(@PathVariable UUID id, @RequestBody java.util.Map<String, String> body) {
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        ProjectMember pm = ensureMembership(project, currentUser);
        if (pm == null || !"OWNER".equalsIgnoreCase(pm.getRole())) {
            return ResponseEntity.status(403).body(
                    java.util.Map.of("message", "Access Denied: Only project owners can manage members. Current role: "
                            + (pm != null ? pm.getRole() : "None")));
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

        com.apimanager.keyvault.model.ProjectMember newMember = com.apimanager.keyvault.model.ProjectMember.builder()
                .project(project)
                .user(userToAdd)
                .role("MEMBER")
                .build();
        projectMemberRepository.save(newMember);

        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/members/remove")
    @Transactional
    public ResponseEntity<?> removeMember(@PathVariable UUID id, @RequestBody java.util.Map<String, String> body) {
        String email = body.get("email");
        Project project = projectRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        ProjectMember pm = ensureMembership(project, currentUser);
        if (pm == null) {
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message", "Access Denied: You are not a member of this project."));
        }

        String role = pm.getRole();
        if (role == null || !"OWNER".equalsIgnoreCase(role)) {
            return ResponseEntity.status(403)
                    .body(java.util.Map.of("message",
                            "Access Denied: Only project owners can remove members. (Your role: " + role + ")"));
        }

        Optional<User> targetUserOpt = userRepository.findByEmail(email.toLowerCase());
        if (targetUserOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(java.util.Map.of("message", "Target user with email '" + email + "' not found."));
        }
        User userToRemove = targetUserOpt.get();

        // Prevent owner from removing themselves
        if (userToRemove.getId().equals(project.getUser().getId())) {
            return ResponseEntity.badRequest()
                    .body(java.util.Map.of("message", "The project owner cannot be removed."));
        }

        projectMemberRepository.deleteByProjectAndUser(project, userToRemove);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/{id}/members")
    @Transactional
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
}
