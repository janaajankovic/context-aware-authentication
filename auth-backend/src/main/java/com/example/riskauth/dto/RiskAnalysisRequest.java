package com.example.riskauth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RiskAnalysisRequest {
    @JsonProperty("user_id")
    private Long userId;

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("user_agent")
    private String userAgent;

    @JsonProperty("login_time")
    private String loginTime;
}