package com.apimanager.keyvault.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.GenericGenerator;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "api_keys")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiKey {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String service;

    @Column(nullable = false)
    private String environment; // dev, test, prod

    @Column(name = "encrypted_value", columnDefinition = "TEXT", nullable = false)
    private String encryptedValue;

    @Column(nullable = false)
    private String iv; // Initialization Vector used for GCM

    @Column(name = "expiry_date")
    private LocalDate expiryDate;

    @Builder.Default
    @Column(name = "current_version")
    private Integer currentVersion = 1;

    public Integer getCurrentVersion() {
        return currentVersion == null ? 1 : currentVersion;
    }

    @OneToMany(mappedBy = "apiKey", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.List<ApiKeyVersion> versions;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
