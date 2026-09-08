package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {
    @Query("SELECT k FROM ApiKey k JOIN FETCH k.project p JOIN FETCH p.user WHERE k.id = :id")
    java.util.Optional<ApiKey> findByIdWithProjectAndUser(@Param("id") UUID id);

    List<ApiKey> findByProject(Project project);

    List<ApiKey> findByExpiryDate(LocalDate date);

    long countByProject(Project project);

    long countByProjectAndExpiryDateBetween(Project project, LocalDate start, LocalDate end);

    @Query("SELECT COUNT(k) FROM ApiKey k JOIN k.project p JOIN ProjectMember pm ON pm.project = p WHERE pm.user = :user AND k.expiryDate BETWEEN :start AND :end")
    long countExpiringKeysForUser(@Param("user") com.apimanager.keyvault.model.User user,
            @Param("start") LocalDate start, @Param("end") LocalDate end);
}
