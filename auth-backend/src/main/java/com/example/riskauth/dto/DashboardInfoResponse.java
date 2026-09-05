package com.example.riskauth.dto;

import com.example.riskauth.model.LoginHistory;
import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class DashboardInfoResponse {
    private String currentIp;
    private String currentUserAgent;
    private String location;
    private double riskScore;
    private String currentStatus;
    private List<LoginHistory> auditTrail;
}