package com.apimanager.keyvault.controller;

import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.UserRepository;
import com.apimanager.keyvault.service.TeamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/projects/{projectId}/members")
public class TeamController {

    @Autowired
    private TeamService teamService;

    @Autowired
    private UserRepository userRepository;

    private User getCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
    }

    @GetMapping
    public ResponseEntity<List<Map<String, String>>> getMembers(@PathVariable UUID projectId) {
        try {
            return ResponseEntity.ok(teamService.getProjectMembers(projectId, getCurrentUser()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).build();
        }
    }

    @PostMapping
    public ResponseEntity<?> addMember(@PathVariable UUID projectId, @RequestBody Map<String, String> body) {
        try {
            String email = body.get("email");
            if (email == null || email.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
            }
            teamService.addMember(projectId, email, getCurrentUser());
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/remove")
    public ResponseEntity<?> removeMember(@PathVariable UUID projectId, @RequestBody Map<String, String> body) {
        try {
            String email = body.get("email");
            if (email == null || email.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email is required"));
            }
            teamService.removeMember(projectId, email, getCurrentUser());
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}
