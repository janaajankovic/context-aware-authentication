package com.example.riskauth.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "login_history")
public class LoginHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String ipAddress;
    private String userAgent;

    // Status prijave (npr. SUCCESS, MFA_REQUIRED, FAILED)
    private String status;

    private LocalDateTime timestamp;

    public LoginHistory() {}

    public LoginHistory(String username, String ipAddress, String userAgent, String status) {
        this.username = username;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.status = status;
        this.timestamp = LocalDateTime.now(); // Automatski beleži trenutno vreme
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}