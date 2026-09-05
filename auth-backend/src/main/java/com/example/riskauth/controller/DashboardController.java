package com.example.riskauth.controller;

import com.example.riskauth.dto.DashboardInfoResponse;
import com.example.riskauth.model.LoginHistory;
import com.example.riskauth.repository.LoginHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "http://localhost:4200")
public class DashboardController {

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    @GetMapping("/info")
    public ResponseEntity<DashboardInfoResponse> getDashboardInfo(Authentication authentication) {
        String username = authentication.getName();

        List<LoginHistory> fullHistory = loginHistoryRepository.findByUsernameOrderByTimestampDesc(username);

        List<LoginHistory> recentHistory = fullHistory.size() > 5 ? fullHistory.subList(0, 5) : fullHistory;

        String currentIp = "Непознато";
        String userAgent = "Непознато";
        String status = "Непознато";
        double riskScore = 0.0;

        if (!recentHistory.isEmpty()) {
            LoginHistory latest = recentHistory.get(0);
            currentIp = latest.getIpAddress();
            userAgent = latest.getUserAgent();
            status = latest.getStatus();

            if (status.contains("MFA_REQUIRED") || status.contains("FAILED")) {
                riskScore = 0.85;
            } else {
                riskScore = 0.15;
            }
        }

        DashboardInfoResponse response = DashboardInfoResponse.builder()
                .currentIp(currentIp)
                .currentUserAgent(userAgent)
                .location("Нови Сад, Србија")
                .riskScore(riskScore)
                .currentStatus(status)
                .auditTrail(recentHistory)
                .build();

        return ResponseEntity.ok(response);
    }
}