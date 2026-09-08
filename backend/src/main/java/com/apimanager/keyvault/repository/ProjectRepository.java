package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.dto.ProjectSummaryDTO;
import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public interface ProjectRepository extends JpaRepository<Project, UUID> {
        List<Project> findByUser(User user);

        @Query("SELECT p FROM Project p JOIN FETCH p.user WHERE p.id = :id")
        java.util.Optional<Project> findByIdWithUser(@Param("id") UUID id);

        @Query("SELECT new com.apimanager.keyvault.dto.ProjectSummaryDTO(" +
                        "p.id, p.name, p.tag, u.email, pm.role, pm.encryptedProjectKey, " +
                        "(SELECT COUNT(k) FROM ApiKey k WHERE k.project = p), " +
                        "(SELECT COUNT(k) FROM ApiKey k WHERE k.project = p AND k.expiryDate BETWEEN :start AND :end)) "
                        +
                        "FROM Project p " +
                        "JOIN p.user u " +
                        "JOIN ProjectMember pm ON pm.project = p " +
                        "WHERE pm.user = :user")
        List<ProjectSummaryDTO> getProjectSummaries(@Param("user") User user,
                        @Param("start") LocalDate start,
                        @Param("end") LocalDate end);
}
