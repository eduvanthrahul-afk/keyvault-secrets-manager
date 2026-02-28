package com.apimanager.keyvault.service;

import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.ProjectMember;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.ProjectMemberRepository;
import com.apimanager.keyvault.repository.ProjectRepository;
import com.apimanager.keyvault.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

@Service
@Transactional
public class TeamService {
    private static final Logger logger = LoggerFactory.getLogger(TeamService.class);

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProjectMemberRepository projectMemberRepository;

    @Autowired
    private AuditService auditService;

    public boolean hasAtLeastRole(String userRole, String requiredRole) {
        if (userRole == null || userRole.isEmpty())
            return false;

        String uRole = userRole.toUpperCase().trim();
        // Support legacy mappings
        if ("MEMBER".equals(uRole))
            uRole = "EDITOR";

        String reqRole = requiredRole != null ? requiredRole.toUpperCase().trim() : "VIEWER";
        if ("MEMBER".equals(reqRole))
            reqRole = "EDITOR";

        List<String> roleHierarchy = Arrays.asList("VIEWER", "EDITOR", "ADMIN", "OWNER");
        int userIdx = roleHierarchy.indexOf(uRole);
        int reqIdx = roleHierarchy.indexOf(reqRole);

        if (userIdx == -1) {
            logger.warn("Unknown user role encountered: {}", uRole);
        }

        return userIdx >= reqIdx && reqIdx != -1;
    }

    public ProjectMember verifyRole(Project project, User user, String requiredRole) {
        ProjectMember pm = ensureMembership(project, user);
        if (!hasAtLeastRole(pm.getRole(), requiredRole)) {
            logger.warn("User {} has role {}, but {} is required for project {}",
                    user.getEmail(), pm.getRole(), requiredRole, project.getName());
            throw new RuntimeException(
                    "Access Denied: You have '" + pm.getRole() + "' role, but '" + requiredRole + "' is required.");
        }
        return pm;
    }

    public List<Map<String, String>> getProjectMembers(UUID projectId, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        // Security check: User must be a member of the project to view the team
        ensureMembership(project, currentUser);

        return projectMemberRepository.findByProject(project).stream()
                .map(m -> {
                    Map<String, String> mData = new HashMap<>();
                    mData.put("email", m.getUser().getEmail());
                    mData.put("role", m.getRole());
                    return mData;
                }).toList();
    }

    public void addMember(UUID projectId, String email, String role, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        ProjectMember pm = ensureMembership(project, currentUser);
        String currentRole = pm.getRole();

        String requestedRole = (role != null && !role.isEmpty()) ? role.toUpperCase() : "VIEWER";
        if (!Arrays.asList("ADMIN", "EDITOR", "VIEWER").contains(requestedRole)) {
            throw new RuntimeException("Invalid role specified.");
        }

        if (!hasAtLeastRole(currentRole, "ADMIN")) {
            throw new RuntimeException("Access Denied: Only project admins or owners can add members.");
        }
        if ("ADMIN".equals(requestedRole) && !"OWNER".equals(currentRole)) {
            throw new RuntimeException("Access Denied: Only owners can add admins.");
        }

        String normalizedEmail = email.toLowerCase().trim();
        User userToAdd = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new RuntimeException("User with email '" + normalizedEmail + "' not found"));

        if (projectMemberRepository.findByProjectAndUser(project, userToAdd).isPresent()) {
            throw new RuntimeException("User is already a member of this project.");
        }

        ProjectMember newMember = ProjectMember.builder()
                .project(project)
                .user(userToAdd)
                .role(requestedRole)
                .build();
        projectMemberRepository.save(newMember);

        auditService.logAction(project, currentUser, "ADD_MEMBER", "TEAM_MEMBER", userToAdd.getId().toString(),
                "Added user " + normalizedEmail + " as " + requestedRole);
        logger.info("User {} added to project {} by {}", normalizedEmail, project.getName(), currentUser.getEmail());
    }

    public void removeMember(UUID projectId, String email, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        ProjectMember pm = ensureMembership(project, currentUser);
        String currentRole = pm.getRole();

        if (!hasAtLeastRole(currentRole, "ADMIN")) {
            throw new RuntimeException("Access Denied: Only project admins can remove members.");
        }

        User userToRemove = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new RuntimeException("User not found"));

        ProjectMember memberToRemove = projectMemberRepository.findByProjectAndUser(project, userToRemove)
                .orElseThrow(() -> new RuntimeException("User is not a member of this project."));

        // Critical: Prevent removing the project owner
        if (userToRemove.getId().equals(project.getUser().getId()) || "OWNER".equals(memberToRemove.getRole())) {
            throw new RuntimeException("The project owner cannot be removed from the team.");
        }

        // Admin cannot remove another admin
        if ("ADMIN".equals(memberToRemove.getRole()) && !"OWNER".equals(currentRole)) {
            throw new RuntimeException("Access Denied: Only owners can remove admins.");
        }

        projectMemberRepository.delete(memberToRemove);
        auditService.logAction(project, currentUser, "REMOVE_MEMBER", "TEAM_MEMBER", userToRemove.getId().toString(),
                "Removed user " + email);
        logger.info("User {} removed from project {} by {}", email, project.getName(), currentUser.getEmail());
    }

    public void updateMemberRole(UUID projectId, String email, String newRole, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        ProjectMember pm = ensureMembership(project, currentUser);
        String currentRole = pm.getRole();

        if (!hasAtLeastRole(currentRole, "ADMIN")) {
            throw new RuntimeException("Access Denied: Only project admins can change roles.");
        }

        String targetRole = (newRole != null && !newRole.isEmpty()) ? newRole.toUpperCase() : "VIEWER";
        if (!Arrays.asList("ADMIN", "EDITOR", "VIEWER").contains(targetRole)) {
            throw new RuntimeException("Invalid role specified.");
        }

        // Only owners can grant ADMIN
        if ("ADMIN".equals(targetRole) && !"OWNER".equals(currentRole)) {
            throw new RuntimeException("Access Denied: Only owners can grant admin roles.");
        }

        User userToUpdate = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new RuntimeException("User not found"));

        ProjectMember memberToUpdate = projectMemberRepository.findByProjectAndUser(project, userToUpdate)
                .orElseThrow(() -> new RuntimeException("User is not a member of this project."));

        if ("OWNER".equals(memberToUpdate.getRole())) {
            throw new RuntimeException("The project owner's role cannot be changed.");
        }

        // Only owners can change an ADMIN's role
        if ("ADMIN".equals(memberToUpdate.getRole()) && !"OWNER".equals(currentRole)) {
            throw new RuntimeException("Access Denied: Only owners can modify an admin's role.");
        }

        memberToUpdate.setRole(targetRole);
        projectMemberRepository.save(memberToUpdate);

        auditService.logAction(project, currentUser, "UPDATE_MEMBER_ROLE", "TEAM_MEMBER",
                userToUpdate.getId().toString(),
                "Changed role of " + email + " to " + targetRole);
        logger.info("User {} role changed to {} in project {} by {}", email, targetRole, project.getName(),
                currentUser.getEmail());
    }

    /**
     * Helper to verify membership and handle owner backfills.
     */
    public ProjectMember ensureMembership(Project project, User user) {
        if (project == null || user == null) {
            throw new RuntimeException("Project or User cannot be null for membership verification");
        }

        UUID pId = project.getId();
        UUID uId = user.getId();
        String uEmail = user.getEmail() != null ? user.getEmail().toLowerCase().trim() : "";

        logger.debug("Verifying membership for user {} ({}) in project {} ({})", uEmail, uId, project.getName(), pId);

        // 1. High priority: Check if user is the explicit owner/creator of the project
        // record
        // We compare IDs directly to avoid proxy issues
        User projectOwner = project.getUser();
        if (projectOwner != null) {
            UUID ownerId = projectOwner.getId();
            if (uId.equals(ownerId) || (uEmail.equalsIgnoreCase(projectOwner.getEmail()) && !uEmail.isEmpty())) {
                logger.debug("User matches project owner ({}). Checking/Provisioning membership record.", uEmail);
                Optional<ProjectMember> existing = projectMemberRepository.findByProjectAndUser(project, user);
                if (existing.isPresent()) {
                    ProjectMember pm = existing.get();
                    if (!"OWNER".equalsIgnoreCase(pm.getRole())) {
                        pm.setRole("OWNER");
                        projectMemberRepository.save(pm);
                    }
                    return pm;
                } else {
                    // Auto-provision owner record
                    ProjectMember owner = ProjectMember.builder()
                            .project(project)
                            .user(user)
                            .role("OWNER")
                            .build();
                    return projectMemberRepository.save(owner);
                }
            }
        }

        // 2. Standard membership check
        Optional<ProjectMember> existing = projectMemberRepository.findByProjectAndUser(project, user);
        if (existing.isPresent()) {
            ProjectMember pm = existing.get();
            // Self-healing for null roles
            if (pm.getRole() == null || pm.getRole().trim().isEmpty()) {
                pm.setRole("EDITOR");
                projectMemberRepository.save(pm);
            }
            return pm;
        }

        // 3. Robust fallback: iterate through all project members as a last resort
        // This helps if findByProjectAndUser fails due to detached/proxy entity
        // mismatch
        List<ProjectMember> allMembers = projectMemberRepository.findByProject(project);
        for (ProjectMember pm : allMembers) {
            User mUser = pm.getUser();
            if (mUser != null) {
                if (uId.equals(mUser.getId()) || (!uEmail.isEmpty() && uEmail.equalsIgnoreCase(mUser.getEmail()))) {
                    logger.debug("Found membership via fallback email/ID check for user {}", uEmail);
                    if (pm.getRole() == null || pm.getRole().trim().isEmpty()) {
                        pm.setRole("EDITOR");
                        projectMemberRepository.save(pm);
                    }
                    return pm;
                }
            }
        }

        logger.error(
                "Security violation: User {} ({}) attempted to access project {} ({}) without valid membership or ownership",
                uEmail, uId, project.getName(), pId);
        throw new RuntimeException("Access Denied: You are not a member of this project.");
    }
}
