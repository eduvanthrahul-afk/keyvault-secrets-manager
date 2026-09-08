package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.model.ApiKeyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface ApiKeyVersionRepository extends JpaRepository<ApiKeyVersion, UUID> {
    List<ApiKeyVersion> findByApiKeyOrderByVersionDesc(ApiKey apiKey);

    void deleteByApiKey(ApiKey apiKey);
}
