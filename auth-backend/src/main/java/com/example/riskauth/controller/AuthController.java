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
import com.example.riskauth.service.LoginAttemptService;
import com.example.riskauth.service.MfaService;
import com.example.riskauth.service.RiskEngineClientService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger auditLogger = LoggerFactory.getLogger(AuthController.class);

    @Autowired private AuthenticationManager authenticationManager;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private UserDetailsService userDetailsService;
    @Autowired private UserRepository userRepository;
    @Autowired private DeviceContextRepository deviceContextRepository;
    @Autowired private ContextExtractionService contextExtractionService;
    @Autowired private RiskEngineClientService riskEngineClientService;
    @Autowired private MfaService mfaService;
    @Autowired private LoginHistoryRepository loginHistoryRepository;
    @Autowired private LoginAttemptService loginAttemptService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest, HttpServletRequest request) {

        String ipAddress = contextExtractionService.extractClientIp(request);
        String userAgent = contextExtractionService.extractUserAgent(request);

        if (loginAttemptService.isBlocked(ipAddress)) {
            // ELK LOG: Blokirana IP adresa zbog Rate Limit-a (WARN)
            auditLogger.warn("AUDIT_ALERT: Blokirana prijava zbog Rate Limit-a za IP: {}", ipAddress);

            loginHistoryRepository.save(new LoginHistory(authRequest.getUsername(), ipAddress, userAgent, "BLOCKED_RATE_LIMIT"));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body("Previše neuspješnih pokušaja. Pokušajte ponovo za 15 minuta.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (Exception e) {
            // REDIS: Bilježimo neuspješan pokušaj
            loginAttemptService.loginFailed(ipAddress);

            // ELK LOG: Pogrešna lozinka (WARN)
            auditLogger.warn("AUDIT_ALERT: Neuspjesna prijava (pogresna lozinka) za korisnika: {} sa IP: {}", authRequest.getUsername(), ipAddress);

            loginHistoryRepository.save(new LoginHistory(authRequest.getUsername(), ipAddress, userAgent, "FAILED_BAD_PASSWORD"));

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Neispravan username ili lozinka");
        }

        // REDIS: Resetujemo brojač jer je šifra ispravna
        loginAttemptService.loginSucceeded(ipAddress);

        User user = userRepository.findByUsername(authRequest.getUsername()).get();
        LocalDateTime now = LocalDateTime.now();
        String timeString = now.format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        RiskAnalysisRequest riskRequest = RiskAnalysisRequest.builder()
                .userId(user.getId())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .loginTime(timeString)
                .build();

        // Sigurno pozivanje Risk Engine-a uz hvatanje tehničke greške
        RiskAnalysisResponse riskResponse;
        try {
            riskResponse = riskEngineClientService.analyzeRisk(riskRequest);
        } catch (Exception e) {
            // ELK LOG: Kritična tehnička greška u komunikaciji sa Risk Engine-om (ERROR)
            auditLogger.error("AUDIT_ERROR: Neuspješna komunikacija sa Risk Engine микросервисом за корисника: {}. Greška: {}", user.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Greшка при анализи ризика.");
        }

        DeviceContext contextLog = new DeviceContext();
        contextLog.setUser(user);
        contextLog.setIpAddress(ipAddress);
        contextLog.setUserAgent(userAgent);
        contextLog.setLoginTimestamp(now);
        contextLog.setSuccessful(true);
        deviceContextRepository.save(contextLog);

        // 8. Policy Engine: Donošenje odluke
        if (riskResponse.isRequiresMfa()) {
            // ELK LOG: Visok rizik, traži se MFA (INFO)
            auditLogger.info("AUDIT_EVENT: Detektovan visok rizik ({}). Zahtijeva se MFA za korisnika: {}", riskResponse.getRiskScore(), user.getUsername());

            loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "MFA_REQUIRED"));

            // Izdajemo PRIVREMENI token
            final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            final String preAuthToken = jwtUtil.generatePreAuthToken(userDetails);

            Map<String, String> response = new HashMap<>();
            response.put("status", "MFA_REQUIRED");
            response.put("preAuthToken", preAuthToken);
            response.put("message", "Rizik je prevelik (" + riskResponse.getRiskScore() + "). Zahteva se MFA.");

            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        }

        // ELK LOG: Uspješna prijava bez MFA (INFO)
        auditLogger.info("AUDIT_EVENT: Uspjesna prijava (nizak rizik) за корисника: {}", user.getUsername());

        // Rizik je mali, vraćamo glavni JWT token
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

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nedostaje Pre-Auth token! Prijavite se prvo lozinkom.");
        }

        String preAuthToken = authHeader.substring(7);

        try {
            // Izvlačimo username direktno iz tokena
            String usernameFromToken = jwtUtil.extractUsername(preAuthToken);

            if (!jwtUtil.isPreAuthToken(preAuthToken) || jwtUtil.extractExpiration(preAuthToken).before(new Date())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token je nevalidan ili je istekao.");
            }

            User user = userRepository.findByUsername(usernameFromToken).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Korisnik nije pronađen");
            }

            boolean isCodeValid = mfaService.verifyCode(user.getMfaSecret(), request.getMfaCode());
            String ipAddress = contextExtractionService.extractClientIp(httpRequest);
            String userAgent = contextExtractionService.extractUserAgent(httpRequest);

            if (!isCodeValid) {
                // ELK LOG: Pogrešan MFA kod (WARN)
                auditLogger.warn("AUDIT_ALERT: Neuspjesna MFA verifikacija (pogresan kod) za korisnika: {} са IP: {}", user.getUsername(), ipAddress);

                loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "FAILED_MFA"));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Neispravan MFA kod!");
            }

            // ELK LOG: Uspješna MFA verifikacija (INFO)
            auditLogger.info("AUDIT_EVENT: Uspjesna MFA verifikacija i prijava za korisника: {}", user.getUsername());

            final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            final String finalJwt = jwtUtil.generateToken(userDetails);

            loginHistoryRepository.save(new LoginHistory(user.getUsername(), ipAddress, userAgent, "SUCCESS_MFA_VERIFIED"));

            return ResponseEntity.ok(new AuthResponse(finalJwt));

        } catch (Exception e) {
            // ELK LOG: Neočekivana sistemska грешка при верификацији (ERROR)
            auditLogger.error("AUDIT_ERROR: Neočekivana sistemska грешка током MFA верификације: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Дошло је до грешке на серверу.");
        }
    }
}