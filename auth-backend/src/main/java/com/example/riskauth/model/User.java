package com.example.riskauth.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "app_users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    // Za MFA integraciju kasnije (čuvaćemo enkriptovan Google Authenticator secret)
    @Column(name = "mfa_secret")
    private String mfaSecret;

    // Veza 1:N - Jedan korisnik može imati više zabeleženih uređaja/konteksta
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<DeviceContext> deviceContexts = new ArrayList<>();
}