package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.MachineToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MachineTokenRepository extends JpaRepository<MachineToken, UUID> {
    List<MachineToken> findByProject_Id(UUID projectId);

    Optional<MachineToken> findByTokenId(String tokenId);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.transaction.annotation.Transactional
    void deleteByProject(com.apimanager.keyvault.model.Project project);
}
