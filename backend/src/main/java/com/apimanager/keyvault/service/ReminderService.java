package com.apimanager.keyvault.service;

import com.apimanager.keyvault.model.ApiKey;
import com.apimanager.keyvault.repository.ApiKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
public class ReminderService {

    @Autowired
    private ApiKeyRepository apiKeyRepository;

    @Autowired
    private JavaMailSender mailSender;

    /**
     * Runs every day at 08:00 AM
     * Finds keys expiring in 7 days and sends a reminder.
     */
    @Scheduled(cron = "0 0 8 * * *")
    public void sendExpiryReminders() {
        LocalDate reminderDate = LocalDate.now().plusDays(7);
        List<ApiKey> expiringKeys = apiKeyRepository.findByExpiryDate(reminderDate);

        for (ApiKey key : expiringKeys) {
            sendEmail(key);
        }
    }

    private void sendEmail(ApiKey key) {
        String userEmail = key.getProject().getUser().getEmail();
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(userEmail);
        message.setSubject("API Key Expiry Reminder: " + key.getName());
        message.setText("Hello,\n\nYour API key '" + key.getName() + "' for service '" + key.getService() +
                "' in project '" + key.getProject().getName() + "' is set to expire on " + key.getExpiryDate() +
                ".\n\nPlease log in to KeyVault to manage your keys.\n\nBest regards,\nKeyVault Team");

        try {
            mailSender.send(message);
        } catch (Exception e) {
            // Log error without exposing user email in logs
            System.err.println("Failed to send expiry reminder email: " + e.getMessage());
        }
    }
}
