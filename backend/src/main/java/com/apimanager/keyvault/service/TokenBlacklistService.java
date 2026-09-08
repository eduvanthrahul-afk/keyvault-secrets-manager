package com.apimanager.keyvault.service;

import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlacklistService {

    private final Map<String, Date> blacklist = new ConcurrentHashMap<>();

    public void blacklistToken(String token, Date expiration) {
        if (token != null && expiration != null) {
            blacklist.put(token, expiration);
        }
    }

    public boolean isBlacklisted(String token) {
        if (token == null)
            return false;
        Date expiration = blacklist.get(token);
        if (expiration == null) {
            return false; // Not blacklisted
        }
        if (expiration.before(new Date())) {
            // Already expired, can be removed from blacklist
            blacklist.remove(token);
            return false;
        }
        return true;
    }
}
