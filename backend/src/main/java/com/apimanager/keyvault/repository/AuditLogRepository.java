package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.AuditLog;
import com.apimanager.keyvault.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    List<AuditLog> findByProjectOrderByCreatedAtDesc(Project project);

    void deleteByProject(Project project);
}
