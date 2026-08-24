package com.example.riskauth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "device_contexts")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeviceContext {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // IP adresa sa koje je izvršen pokušaj prijave
    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    // Podaci o pregledaču i operativnom sistemu
    @Column(name = "user_agent", nullable = false, length = 512)
    private String userAgent;

    // Grad/Država koju ćemo dobijati mapiranjem IP adrese
    private String location;

    // Vreme pokušaja prijave
    @Column(name = "login_timestamp", nullable = false)
    private LocalDateTime loginTimestamp;

    // Da li je prijava bila uspešna
    @Column(name = "is_successful")
    private boolean isSuccessful;

    // Strani ključ ka korisniku
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;
}