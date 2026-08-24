package com.example.riskauth.repository;

import com.example.riskauth.model.DeviceContext;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeviceContextRepository extends JpaRepository<DeviceContext, Long> {
    // Pronalazi sve uređaje sa kojih se određeni korisnik prijavljivao
    List<DeviceContext> findByUserIdOrderByLoginTimestampDesc(Long userId);
}