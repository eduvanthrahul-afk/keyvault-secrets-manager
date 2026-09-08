package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.AuditLog;
import com.apimanager.keyvault.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    List<AuditLog> findByProjectOrderByCreatedAtDesc(Project project);

    List<AuditLog> findByProjectAndCreatedAtAfterOrderByCreatedAtDesc(Project project, LocalDateTime date);

    void deleteByProject(Project project);
}
