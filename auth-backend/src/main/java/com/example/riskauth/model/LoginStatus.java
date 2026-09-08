package com.example.riskauth.model;

public enum LoginStatus {
    SUCCESS_LOW_RISK,
    MFA_REQUIRED,
    BLOCKED_RATE_LIMIT,
    FAILED_BAD_PASSWORD,
    FAILED_MFA,
    SUCCESS_MFA_VERIFIED
}