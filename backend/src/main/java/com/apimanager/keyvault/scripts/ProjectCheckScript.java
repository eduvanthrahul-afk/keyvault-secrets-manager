package com.apimanager.keyvault.scripts;

import com.apimanager.keyvault.repository.ProjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class ProjectCheckScript implements CommandLineRunner {
    @Autowired
    private ProjectRepository repo;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("--- PROJECT CHECK START ---");
        repo.findAll().forEach(p -> {
            System.out.println("Project: " + p.getName() + " | ID: " + p.getId() + " | Owner ID: "
                    + (p.getUser() != null ? p.getUser().getId() : "NULL"));
        });
        System.out.println("--- PROJECT CHECK END ---");
    }
}
