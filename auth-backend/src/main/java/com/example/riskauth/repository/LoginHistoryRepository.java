package com.example.riskauth.repository;

import com.example.riskauth.model.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {
    // Dodajemo ovu metodu jer će nam kasnije trebati da Python dovuče istoriju za određenog korisnika
    List<LoginHistory> findByUsernameOrderByTimestampDesc(String username);
}