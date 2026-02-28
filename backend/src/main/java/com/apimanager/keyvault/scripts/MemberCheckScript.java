package com.apimanager.keyvault.scripts;

import com.apimanager.keyvault.repository.ProjectMemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class MemberCheckScript implements CommandLineRunner {
    @Autowired
    private ProjectMemberRepository repo;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        System.out.println("--- MEMBER CHECK START ---");
        repo.findAll().forEach(pm -> {
            try {
                System.out.println("User: " + pm.getUser().getEmail() + " | Project: " + pm.getProject().getName()
                        + " | Role: " + pm.getRole());
            } catch (Exception e) {
                System.out.println("Error loading member details: " + e.getMessage());
            }
        });
        System.out.println("--- MEMBER CHECK END ---");
    }
}
