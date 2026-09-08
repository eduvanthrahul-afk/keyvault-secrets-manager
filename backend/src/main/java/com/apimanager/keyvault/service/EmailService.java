package com.apimanager.keyvault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${resend.api.key:re_placeholder}")
    private String resendApiKey;

    @Value("${resend.from.email:onboarding@resend.dev}")
    private String fromEmail;

    public void sendOtpEmail(String to, String otp) {
        String url = "https://api.resend.com/emails";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(resendApiKey);

        Map<String, Object> body = new HashMap<>();
        body.put("from", "Kypher <" + fromEmail + ">");
        body.put("to", to);
        body.put("subject", "Verify Your Identity | Kypher");
        body.put("html",
                "<div style='font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;'>"
                        +
                        "<h2 style='color: #0f172a; margin-bottom: 24px;'>Secure Enrollment Verification</h2>" +
                        "<p style='color: #475569; font-size: 16px; line-height: 1.6;'>You are creating a Zero-Knowledge security vault. Please use the following one-time passcode to verify your email address:</p>"
                        +
                        "<div style='background: #f8fafc; padding: 24px; border-radius: 8px; text-align: center; margin: 32px 0;'>"
                        +
                        "<span style='font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #3b82f6;'>" + otp
                        + "</span>" +
                        "</div>" +
                        "<p style='color: #94a3b8; font-size: 14px;'>This code will expire in 5 minutes. If you did not request this, please ignore this email.</p>"
                        +
                        "<hr style='border: 0; border-top: 1px solid #e2e8f0; margin: 32px 0;' />" +
                        "<p style='color: #94a3b8; font-size: 12px; text-align: center;'>&copy; 2026 Kypher Security Systems. All rights reserved.</p>"
                        +
                        "</div>");

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("OTP email sent successfully to {}", to);
            } else {
                logger.error("Failed to send email via Resend: {}", response.getBody());
            }
        } catch (Exception e) {
            logger.error("Error sending email via Resend", e);
            // We don't throw here to avoid breaking the registration flow if email service
            // is down
            // but in a real app, you might want to handle this.
        }
    }
}
