package com.apimanager.keyvault.scripts;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordHasher {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String password = args.length > 0 ? args[0] : "DemoPass123!";
        System.out.println("--- RESULT START ---");
        System.out.println(encoder.encode(password));
        System.out.println("--- RESULT END ---");
    }
}
