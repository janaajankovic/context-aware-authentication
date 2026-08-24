package com.example.riskauth.dto;

import lombok.Data;

@Data
public class MfaVerificationRequest {
    private String username;
    private int mfaCode;
}