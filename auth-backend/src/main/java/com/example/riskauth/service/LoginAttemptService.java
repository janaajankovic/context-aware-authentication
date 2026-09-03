package com.example.riskauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private final int MAX_ATTEMPT = 5;
    private final int BLOCK_DURATION_MINUTES = 15;

    @Autowired
    private StringRedisTemplate redisTemplate;

    public void loginFailed(String ipAddress) {
        String key = "login_attempt:" + ipAddress;
        Long attempts = redisTemplate.opsForValue().increment(key);
        System.out.println(">>> REDIS: Neuspjesan pokusaj broj: " + attempts + " za IP: " + ipAddress);

        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, BLOCK_DURATION_MINUTES, TimeUnit.MINUTES);
        }
    }

    public void loginSucceeded(String ipAddress) {
        redisTemplate.delete("login_attempt:" + ipAddress);
    }

    public boolean isBlocked(String ipAddress) {
        String key = "login_attempt:" + ipAddress;
        String attempts = redisTemplate.opsForValue().get(key);
        if (attempts != null) {
            return Integer.parseInt(attempts) >= MAX_ATTEMPT;
        }
        return false;
    }
}
