package com.example.riskauth.service;

import com.example.riskauth.dto.RiskAnalysisRequest;
import com.example.riskauth.dto.RiskAnalysisResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class RiskEngineClientService {

    private final RestTemplate restTemplate;
    private final String pythonEngineUrl;

    // Ako varijabla RISK_ENGINE_URL nije setovana u sistemskim varijablama, koristiće localhost:8001
    public RiskEngineClientService(
            RestTemplate restTemplate,
            @Value("${RISK_ENGINE_URL:http://localhost:8001/api/analyze-risk}") String pythonEngineUrl) {
        this.restTemplate = restTemplate;
        this.pythonEngineUrl = pythonEngineUrl;
    }

    public RiskAnalysisResponse analyzeRisk(RiskAnalysisRequest request) {
        try {
            ResponseEntity<RiskAnalysisResponse> response = restTemplate.postForEntity(
                    pythonEngineUrl,
                    request,
                    RiskAnalysisResponse.class
            );
            return response.getBody();

        } catch (Exception e) {
            System.err.println("KRITIČNO: Python Risk Engine nije dostupan! Razlog: " + e.getMessage());

            RiskAnalysisResponse failSafeResponse = new RiskAnalysisResponse();
            failSafeResponse.setRiskScore(1.0);
            failSafeResponse.setRequiresMfa(true);
            return failSafeResponse;
        }
    }
}