package com.example.riskauth.controller;

import com.example.riskauth.dto.*;
import com.example.riskauth.model.DeviceContext;
import com.example.riskauth.model.User;
import com.example.riskauth.repository.DeviceContextRepository;
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

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest, HttpServletRequest request) {

        // 1. Provera šifre
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (Exception e) {
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
            // Rizik je previsok, za sada vraćamo poruku (u sledećoj fazi ovde ide Google Authenticator)
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Rizik je prevelik (" + riskResponse.getRiskScore() + "). Zahteva se MFA: " + riskResponse.getReasons());
        }

        // Rizik je mali, vraćamo JWT token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody MfaVerificationRequest request) {
        User user = userRepository.findByUsername(request.getUsername()).orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Korisnik nije pronađen");
        }

        // Proveravamo da li se kod sa telefona poklapa sa onim što algoritam očekuje
        boolean isCodeValid = mfaService.verifyCode(user.getMfaSecret(), request.getMfaCode());

        if (!isCodeValid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Neispravan MFA kod!");
        }

        // Ako je kod tačan, izdajemo JWT token (Korisnik je uspešno otključao nalog)
        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }
}