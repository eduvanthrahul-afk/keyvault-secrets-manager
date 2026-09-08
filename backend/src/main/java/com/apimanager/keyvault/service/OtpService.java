package com.apimanager.keyvault.service;

import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class OtpService {
    private final Map<String, String> otpCache = new ConcurrentHashMap<>();
    private final Map<String, Boolean> verifiedTickets = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final SecureRandom random = new SecureRandom();

    public String generateOtp(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        String otp = String.format("%06d", random.nextInt(1000000));
        otpCache.put(normalizedEmail, otp);

        // Remove any old verification tickets if generating a new OTP
        verifiedTickets.remove(normalizedEmail);

        // Expire after 5 minutes
        scheduler.schedule(() -> otpCache.remove(normalizedEmail), 5, TimeUnit.MINUTES);

        return otp;
    }

    public boolean verifyOtp(String email, String code) {
        if (code == null || code.isEmpty())
            return false;
        String normalizedEmail = email.toLowerCase().trim();
        String cachedOtp = otpCache.get(normalizedEmail);

        if (cachedOtp != null && cachedOtp.equals(code.trim())) {
            otpCache.remove(normalizedEmail);

            // Mark as verified for registration
            verifiedTickets.put(normalizedEmail, true);
            // Ticket expires in 15 minutes
            scheduler.schedule(() -> verifiedTickets.remove(normalizedEmail), 15, TimeUnit.MINUTES);

            return true;
        }
        return false;
    }

    public boolean isEmailVerified(String email) {
        if (email == null)
            return false;
        return verifiedTickets.getOrDefault(email.toLowerCase().trim(), false);
    }

    public void consumeTicket(String email) {
        if (email != null) {
            verifiedTickets.remove(email.toLowerCase().trim());
        }
    }
}
