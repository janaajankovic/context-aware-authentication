package com.example.riskauth.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class ContextExtractionService {

    public String extractClientIp(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");

        if (clientIp == null || clientIp.isEmpty() || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getRemoteAddr();
        }

        // Ako prolazi kroz više proxy-ja, uzimamo prvu IP adresu u nizu
        if (clientIp != null && clientIp.contains(",")) {
            clientIp = clientIp.split(",")[0].trim();
        }

        return clientIp;
    }

    // Izdvaja User-Agent (tip uređaja, browser, operativni sistem)
    public String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return (userAgent != null) ? userAgent : "Unknown Device";
    }
}