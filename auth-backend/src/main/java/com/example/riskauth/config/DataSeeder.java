package com.example.riskauth.config;

import com.example.riskauth.model.User;
import com.example.riskauth.repository.UserRepository;
import com.example.riskauth.service.MfaService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, MfaService mfaService) {
        return args -> {
            Optional<User> optionalUser = userRepository.findByUsername("testuser");
            User user;

            // Proveravamo da li korisnik postoji, ako ne, kreiramo ga
            if (optionalUser.isEmpty()) {
                user = new User();
                user.setUsername("testuser");
                user.setPassword("master2026");
                user.setEmail("test@ftn.uns.ac.rs");
            } else {
                user = optionalUser.get();
            }

            // Ako korisnik NEMA MFA ključ, generišemo ga
            if (user.getMfaSecret() == null || user.getMfaSecret().isEmpty()) {
                String secret = mfaService.generateSecretKey();
                user.setMfaSecret(secret);
                userRepository.save(user);

                String qrCodeUrl = mfaService.getQrCodeUrl(user.getUsername(), secret);

                System.out.println("======== MFA POSTAVLJEN ZA TEST KORISNIKA ========");
                System.out.println("Skeniraj ovaj link u pregledaču da dobiješ QR kod:");
                System.out.println(qrCodeUrl);
                System.out.println("MFA Secret: " + secret);
                System.out.println("==================================================");
            } else {
                // Ako korisnik VEĆ IMA ključ, samo ispisujemo ažurirani QR link
                String qrCodeUrl = mfaService.getQrCodeUrl(user.getUsername(), user.getMfaSecret());

                System.out.println("======== TEST KORISNIK VEĆ IMA MFA ========");
                System.out.println("Novi (ispravljeni) QR kod link:");
                System.out.println(qrCodeUrl);
                System.out.println("MFA Secret: " + user.getMfaSecret());
                System.out.println("===========================================");
            }
        };
    }
}