package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.dto.ApiKeyDTO;
import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.ApiKeyRepository;
import com.apimanager.keyvault.repository.ProjectRepository;
import com.apimanager.keyvault.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping
public class ApiKeyController {

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private com.apimanager.keyvault.repository.ProjectMemberRepository projectMemberRepository;

    private User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername()).orElseThrow();
    }

    @GetMapping("/projects/{projectId}/keys")
    public ResponseEntity<List<ApiKeyDTO>> getKeysByProject(@PathVariable UUID projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow();
        User currentUser = getCurrentUser();

        // Check if user is a member of the project
        if (projectMemberRepository.findByProjectAndUser(project, currentUser).isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        List<ApiKeyDTO> keys = apiKeyRepository.findByProject(project).stream().map(this::convertToDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(keys);
    }

    @PostMapping("/keys")
    public ResponseEntity<ApiKeyDTO> createKey(@RequestBody ApiKeyDTO dto) {
        Project project = projectRepository.findById(dto.getProjectId()).orElseThrow();
        User currentUser = getCurrentUser();

        // Check if user is a member of the project
        if (projectMemberRepository.findByProjectAndUser(project, currentUser).isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        ApiKey key = ApiKey.builder()
                .name(dto.getName())
                .service(dto.getService())
                .environment(dto.getEnvironment())
                .encryptedValue(dto.getEncryptedValue())
                .iv(dto.getIv())
                .expiryDate(dto.getExpiryDate())
                .notes(dto.getNotes())
                .project(project)
                .build();

        ApiKey saved = apiKeyRepository.save(key);
        return ResponseEntity.ok(convertToDTO(saved));
    }

    @PutMapping("/keys/{id}")
    public ResponseEntity<ApiKeyDTO> updateKey(@PathVariable UUID id, @RequestBody ApiKeyDTO dto) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        // Check if user is a member of the project
        if (projectMemberRepository.findByProjectAndUser(key.getProject(), currentUser).isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        key.setName(dto.getName());
        key.setService(dto.getService());
        key.setEnvironment(dto.getEnvironment());
        key.setEncryptedValue(dto.getEncryptedValue());
        key.setIv(dto.getIv());
        key.setExpiryDate(dto.getExpiryDate());
        key.setNotes(dto.getNotes());

        apiKeyRepository.save(key);
        return ResponseEntity.ok(convertToDTO(key));
    }

    @DeleteMapping("/keys/{id}")
    public ResponseEntity<?> deleteKey(@PathVariable UUID id) {
        ApiKey key = apiKeyRepository.findById(id).orElseThrow();
        User currentUser = getCurrentUser();

        // Check if user is a member of the project
        if (projectMemberRepository.findByProjectAndUser(key.getProject(), currentUser).isEmpty()) {
            return ResponseEntity.status(403).build();
        }

        apiKeyRepository.delete(key);
        return ResponseEntity.ok().build();
    }

    private ApiKeyDTO convertToDTO(ApiKey key) {
        ApiKeyDTO dto = new ApiKeyDTO();
        dto.setId(key.getId());
        dto.setProjectId(key.getProject().getId());
        dto.setName(key.getName());
        dto.setService(key.getService());
        dto.setEnvironment(key.getEnvironment());
        dto.setEncryptedValue(key.getEncryptedValue());
        dto.setIv(key.getIv());
        dto.setExpiryDate(key.getExpiryDate());
        dto.setNotes(key.getNotes());
        return dto;
    }
}
