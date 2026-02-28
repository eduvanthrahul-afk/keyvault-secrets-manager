package com.apimanager.keyvault.scripts;

import com.apimanager.keyvault.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class UserCheckScript implements CommandLineRunner {
    @Autowired
    private UserRepository repo;

    @Override
    public void run(String... args) throws Exception {
        System.out.println("--- USER CHECK START ---");
        repo.findAll().forEach(u -> {
            System.out.println("User: " + u.getEmail() + " | ID: " + u.getId());
        });
        System.out.println("--- USER CHECK END ---");
    }
}
