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

    public void addMember(UUID projectId, String email, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        ProjectMember pm = ensureMembership(project, currentUser);
        if (!"OWNER".equalsIgnoreCase(pm.getRole())) {
            throw new RuntimeException("Access Denied: Only project owners can manage members.");
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
                .role("MEMBER")
                .build();
        projectMemberRepository.save(newMember);
        logger.info("User {} added to project {} by {}", normalizedEmail, project.getName(), currentUser.getEmail());
    }

    public void removeMember(UUID projectId, String email, User currentUser) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found"));

        ProjectMember pm = ensureMembership(project, currentUser);
        if (!"OWNER".equalsIgnoreCase(pm.getRole())) {
            throw new RuntimeException("Access Denied: Only project owners can remove members.");
        }

        User userToRemove = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new RuntimeException("User not found"));

        ProjectMember memberToRemove = projectMemberRepository.findByProjectAndUser(project, userToRemove)
                .orElseThrow(() -> new RuntimeException("User is not a member of this project."));

        // Critical: Prevent removing the project owner
        if (userToRemove.getId().equals(project.getUser().getId())) {
            throw new RuntimeException("The project owner cannot be removed from the team.");
        }

        projectMemberRepository.delete(memberToRemove);
        logger.info("User {} removed from project {} by {}", email, project.getName(), currentUser.getEmail());
    }

    /**
     * Helper to verify membership and handle owner backfills.
     */
    public ProjectMember ensureMembership(Project project, User user) {
        Optional<ProjectMember> existing = projectMemberRepository.findByProjectAndUser(project, user);
        if (existing.isPresent()) {
            return existing.get();
        }

        // Casing fallback
        List<ProjectMember> allMembers = projectMemberRepository.findByProject(project);
        for (ProjectMember pm : allMembers) {
            if (pm.getUser().getEmail().equalsIgnoreCase(user.getEmail())) {
                return pm;
            }
        }

        // Owner auto-backfill for legacy data
        if (project.getUser() != null && project.getUser().getId().equals(user.getId())) {
            ProjectMember owner = ProjectMember.builder()
                    .project(project)
                    .user(user)
                    .role("OWNER")
                    .build();
            return projectMemberRepository.save(owner);
        }

        throw new RuntimeException("Access Denied: You are not a member of this project.");
    }
}
