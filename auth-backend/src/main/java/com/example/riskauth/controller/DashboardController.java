package com.example.riskauth.controller;

import com.example.riskauth.dto.DashboardInfoResponse;
import com.example.riskauth.model.DeviceContext;
import com.example.riskauth.model.LoginHistory;
import com.example.riskauth.model.LoginStatus;
import com.example.riskauth.model.User;
import com.example.riskauth.repository.LoginHistoryRepository;
import com.example.riskauth.repository.UserRepository;
import com.example.riskauth.service.MfaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "http://localhost:4200")
public class DashboardController {

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private MfaService mfaService;

    @GetMapping("/info")
    public ResponseEntity<DashboardInfoResponse> getDashboardInfo(Authentication authentication) {
        String username = authentication.getName();

        User user = userRepository.findByUsername(username).orElseThrow();
        String qrCodeBase64 = mfaService.getQrCodeImageBase64(user.getUsername(), user.getMfaSecret());

        List<LoginHistory> fullHistory = loginHistoryRepository.findByUsernameOrderByTimestampDesc(username);
        List<LoginHistory> recentHistory = fullHistory.size() > 10 ? fullHistory.subList(0, 10) : fullHistory;

        String currentIp = "Nepoznato";
        String userAgent = "Nepoznato";
        LoginStatus status = LoginStatus.SUCCESS_LOW_RISK;
        double riskScore = 0.0;
        String location = "Nepoznato";

        if (!recentHistory.isEmpty()) {
            LoginHistory latest = recentHistory.get(0);
            currentIp = latest.getIpAddress();
            userAgent = latest.getUserAgent();

            // Rešen problem sa statusom: sada se direktno prosleđuje Enum,
            // a frontend će ga ispravno prikazati bez potrebe za .contains() proverama.
            status = latest.getStatus();

            // Prava vrednost iz baze podataka koju je izračunao Python Risk Engine
            if (latest.getRiskScore() != null) {
                riskScore = latest.getRiskScore();
            }

            if (user.getDeviceContexts() != null && !user.getDeviceContexts().isEmpty()) {
                DeviceContext latestDevice = user.getDeviceContexts().stream()
                        .max(Comparator.comparing(DeviceContext::getLoginTimestamp))
                        .orElse(null);

                if (latestDevice != null && latestDevice.getLocation() != null) {
                    String city = latestDevice.getLocation().getCity();
                    String country = latestDevice.getLocation().getCountry();

                    if (city != null && country != null) {
                        location = city + ", " + country;
                    } else if (country != null) {
                        location = country;
                    }
                }
            }
        }

        DashboardInfoResponse response = DashboardInfoResponse.builder()
                .currentIp(currentIp)
                .currentUserAgent(userAgent)
                .location(location)
                .riskScore(riskScore)
                .currentStatus(status)
                .mfaQrCode(qrCodeBase64)
                .auditTrail(recentHistory)
                .build();

        return ResponseEntity.ok(response);
    }
}