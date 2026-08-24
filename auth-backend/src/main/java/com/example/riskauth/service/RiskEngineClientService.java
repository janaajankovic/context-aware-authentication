package com.example.riskauth.service;

import com.example.riskauth.dto.RiskAnalysisRequest;
import com.example.riskauth.dto.RiskAnalysisResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class RiskEngineClientService {

    @Autowired
    private RestTemplate restTemplate;

    // Putanja do tvog Python servisa
    private final String pythonEngineUrl = "http://localhost:8001/api/analyze-risk";

    public RiskAnalysisResponse analyzeRisk(RiskAnalysisRequest request) {
        ResponseEntity<RiskAnalysisResponse> response = restTemplate.postForEntity(
                pythonEngineUrl,
                request,
                RiskAnalysisResponse.class
        );
        return response.getBody();
    }
}