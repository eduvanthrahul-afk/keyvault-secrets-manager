package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {
    List<ApiKey> findByProject(Project project);
    List<ApiKey> findByExpiryDate(LocalDate date);
}
