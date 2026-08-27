package com.example.riskauth.controller;

import com.example.riskauth.dto.*;
import com.example.riskauth.model.DeviceContext;
import com.example.riskauth.model.LoginHistory;
import com.example.riskauth.model.User;
import com.example.riskauth.repository.DeviceContextRepository;
import com.example.riskauth.repository.LoginHistoryRepository;
import com.example.riskauth.repository.UserRepository;
import com.example.riskauth.security.JwtUtil;
import com.example.riskauth.service.ContextExtractionService;
import com.example.riskauth.service.MfaService;
import com.example.riskauth.service.RiskEngineClientService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private UserDetailsService userDetailsService;
    @Autowired private UserRepository userRepository;
    @Autowired private DeviceContextRepository deviceContextRepository;
    @Autowired private ContextExtractionService contextExtractionService;
    @Autowired private RiskEngineClientService riskEngineClientService;
    @Autowired private MfaService mfaService;
    @Autowired private LoginHistoryRepository loginHistoryRepository;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest, HttpServletRequest request) {

        // 1. Provera šifre
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (Exception e) {
            String ipAddress = contextExtractionService.extractClientIp(request);
            String userAgent = contextExtractionService.extractUserAgent(request);
            loginHistoryRepository.save(new LoginHistory(authRequest.getUsername(), ipAddress, userAgent, "FAILED_BAD_PASSWORD"));

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Neispravan username ili lozinka");
        }

        // 2. Izdvajanje korisnika i konteksta (IP, User-Agent, Vreme)
        User user = userRepository.findByUsername(authRequest.getUsername()).get();
        String ipAddress = contextExtractionService.extractClientIp(request);
        String userAgent = contextExtractionService.extractUserAgent(request);
        LocalDateTime now = LocalDateTime.now();
        String timeString = now.format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        // 3. Pakovanje podataka za Python Risk Engine
        RiskAnalysisRequest riskRequest = RiskAnalysisRequest.builder()
                .userId(user.getId())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .loginTime(timeString)
                .build();

        // 4. Komunikacija sa Pythonom
        RiskAnalysisResponse riskResponse = riskEngineClientService.analyzeRisk(riskRequest);

        // 5. Čuvanje istorije u bazu
        DeviceContext contextLog = new DeviceContext();
        contextLog.setUser(user);
        contextLog.setIpAddress(ipAddress);
        contextLog.setUserAgent(userAgent);
        contextLog.setLoginTimestamp(now);
        contextLog.setSuccessful(true);
        deviceContextRepository.save(contextLog);

        // 6. Policy Engine: Donošenje odluke
        if (riskResponse.isRequiresMfa()) {
            loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "MFA_REQUIRED"));

            // NOVO: Izdajemo PRIVREMENI token
            final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            final String preAuthToken = jwtUtil.generatePreAuthToken(userDetails);

            // Šaljemo ga nazad klijentu uz status 202 (Accepted) umesto 403 (Forbidden)
            Map<String, String> response = new HashMap<>();
            response.put("status", "MFA_REQUIRED");
            response.put("preAuthToken", preAuthToken);
            response.put("message", "Rizik je prevelik (" + riskResponse.getRiskScore() + "). Zahteva se MFA.");

            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        }

        // Rizik je mali, vraćamo JWT token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);

        loginHistoryRepository.save(new LoginHistory(
                user.getUsername(),
                ipAddress,
                userAgent,
                "SUCCESS_LOW_RISK"
        ));

        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody MfaVerificationRequest request,
            HttpServletRequest httpRequest) {

        // 1. BEZBEDNOSNA PROVERA: Da li je korisnik uopšte prošao prvi korak?
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nedostaje Pre-Auth token! Prijavite se prvo lozinkom.");
        }

        String preAuthToken = authHeader.substring(7);

        try {
            // Izvlačimo username direktno iz tokena (tako da napadač ne može da podmetne tuđe ime u JSON-u)
            String usernameFromToken = jwtUtil.extractUsername(preAuthToken);

            if (!jwtUtil.isPreAuthToken(preAuthToken) || jwtUtil.extractExpiration(preAuthToken).before(new Date())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token je nevalidan ili je istekao.");
            }

            User user = userRepository.findByUsername(usernameFromToken).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Korisnik nije pronađen");
            }

            // 2. Provera MFA koda
            boolean isCodeValid = mfaService.verifyCode(user.getMfaSecret(), request.getMfaCode());
            String ipAddress = contextExtractionService.extractClientIp(httpRequest);
            String userAgent = contextExtractionService.extractUserAgent(httpRequest);

            if (!isCodeValid) {
                loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "FAILED_MFA"));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Neispravan MFA kod!");
            }

            // 3. USPEH: Izdavanje PRAVOG tokena (sa punim pravima)
            final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            final String finalJwt = jwtUtil.generateToken(userDetails);

            loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "SUCCESS_MFA_VERIFIED"));

            return ResponseEntity.ok(new AuthResponse(finalJwt));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nevalidan token struktura!");
        }
    }
}