package com.apimanager.keyvault.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.GenericGenerator;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "api_key_versions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiKeyVersion {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "api_key_id", nullable = false)
    private ApiKey apiKey;

    @Column(nullable = false)
    private int version;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String service;

    @Column(nullable = false)
    private String environment;

    @Column(name = "encrypted_value", columnDefinition = "TEXT", nullable = false)
    private String encryptedValue;

    @Column(nullable = false)
    private String iv;

    @Column(name = "expiry_date")
    private java.time.LocalDate expiryDate;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "updated_by")
    private String updatedBy;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
