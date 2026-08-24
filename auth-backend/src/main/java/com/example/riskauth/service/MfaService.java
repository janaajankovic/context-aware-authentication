package com.example.riskauth.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class MfaService {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String generateSecretKey() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }

    public String getQrCodeUrl(String username, String secret) {
        String issuer = "RiskAuth-Master";
        String otpauthUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer, username, secret, issuer);

        // Koristimo qrserver API 
        return "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data="
                + URLEncoder.encode(otpauthUri, StandardCharsets.UTF_8);
    }
}