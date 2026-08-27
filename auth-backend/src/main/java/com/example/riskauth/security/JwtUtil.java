package com.example.riskauth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    // Čitamo fiksni tajni ključ iz sistemskih varijabli
    private static final String JWT_SECRET_STRING = System.getenv("JWT_SECRET");

    // Token traje 10 sati
    private final long EXPIRATION_TIME = 1000 * 60 * 60 * 10;
    private final long PRE_AUTH_EXPIRATION_TIME = 1000 * 60 * 5;

    public JwtUtil() {
        // Fail-Fast sigurnosna provera: Ključ mora postojati i mora biti dug najmanje 32 karaktera (256 bita)
        if (JWT_SECRET_STRING == null || JWT_SECRET_STRING.length() < 32) {
            throw new IllegalStateException("KRITIČNA BEZBEDNOSNA GREŠKA: JWT_SECRET nije setovan u sistemskim varijablama ili je kraći od 32 karaktera!");
        }
    }

    // Metoda za pretvaranje našeg stringa u validan kriptografski ključ
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(JWT_SECRET_STRING.getBytes());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        // Dinamički ključ zamenjen fiksiranim getSigningKey()
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    // Generiše token koji dokazuje da je lozinka tačna, ali zabranjuje pristup sistemu
    public String generatePreAuthToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("isPreAuth", true); // Ovo ga razlikuje od pravog tokena
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + PRE_AUTH_EXPIRATION_TIME))
                .signWith(getSigningKey())
                .compact();
    }

    // Proverava da li je token samo privremeni
    public Boolean isPreAuthToken(String token) {
        Boolean isPreAuth = extractClaim(token, claims -> claims.get("isPreAuth", Boolean.class));
        return isPreAuth != null && isPreAuth;
    }
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey()) // Dinamički ključ zamenjen fiksiranim getSigningKey()
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}