package com.example.riskauth.config;

import com.example.riskauth.model.User;
import com.example.riskauth.repository.UserRepository;
import com.example.riskauth.service.MfaService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder; // DODATO

import java.util.Optional;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, MfaService mfaService, PasswordEncoder passwordEncoder) {
        return args -> {
            Optional<User> optionalUser = userRepository.findByUsername("testuser");
            User user;
            boolean needsSave = false;

            if (optionalUser.isEmpty()) {
                user = new User();
                user.setUsername("testuser");
                user.setPassword(passwordEncoder.encode("master2026"));
                user.setEmail("test@ftn.uns.ac.rs");
                needsSave = true;
            } else {
                user = optionalUser.get();
                if (!user.getPassword().startsWith("$2a$")) {
                    user.setPassword(passwordEncoder.encode(user.getPassword()));
                    needsSave = true;
                }
            }

            // Ako korisnik NEMA MFA ključ, generišemo ga
            if (user.getMfaSecret() == null || user.getMfaSecret().isEmpty()) {
                String secret = mfaService.generateSecretKey();
                user.setMfaSecret(secret);
                needsSave = true;

                String qrCodeUrl = mfaService.getQrCodeImageBase64(user.getUsername(), secret);
                System.out.println("Skeniraj ovaj link u pregledaču da dobiješ QR kod:");
                System.out.println(qrCodeUrl);
            } else {
                // Ako korisnik VEĆ IMA ključ, samo ispisujemo ažurirani QR link
                String qrCodeUrl = mfaService.getQrCodeImageBase64(user.getUsername(), user.getMfaSecret());
                System.out.println("Novi (ispravljeni) QR kod link:");
                System.out.println(qrCodeUrl);
            }

            if (needsSave) {
                userRepository.save(user);
            }
        };
    }
}