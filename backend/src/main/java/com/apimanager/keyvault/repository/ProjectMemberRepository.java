package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.ProjectMember;
import com.apimanager.keyvault.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ProjectMemberRepository extends JpaRepository<ProjectMember, UUID> {
    List<ProjectMember> findByUser(User user);

    List<ProjectMember> findByProject(Project project);

    Optional<ProjectMember> findByProjectAndUser(Project project, User user);

    void deleteByProjectAndUser(Project project, User user);
}
