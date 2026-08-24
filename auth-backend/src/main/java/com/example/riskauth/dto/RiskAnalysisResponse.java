package com.example.riskauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class RiskAnalysisResponse {
    @JsonProperty("risk_score")
    private double riskScore;

    private List<String> reasons;

    @JsonProperty("requires_mfa")
    private boolean requiresMfa;
}