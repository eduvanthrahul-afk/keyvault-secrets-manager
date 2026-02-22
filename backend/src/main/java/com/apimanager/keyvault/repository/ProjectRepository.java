package com.apimanager.keyvault.repository;

import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface ProjectRepository extends JpaRepository<Project, UUID> {
    List<Project> findByUser(User user);
}
