package com.apimanager.keyvault.service;

import com.apimanager.keyvault.model.AuditLog;
import com.apimanager.keyvault.model.Project;
import com.apimanager.keyvault.model.User;
import com.apimanager.keyvault.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuditService {
    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private HttpServletRequest request;

    public void logAction(Project project, User user, String action, String targetType, String targetId,
            String details) {
        String ipAddress = request != null ? request.getRemoteAddr() : "UNKNOWN";
        AuditLog auditLog = AuditLog.builder()
                .project(project)
                .user(user)
                .action(action)
                .targetType(targetType)
                .targetId(targetId)
                .details(details)
                .ipAddress(ipAddress)
                .build();
        auditLogRepository.save(auditLog);
    }
}
