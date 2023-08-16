package com.example.jwttokenmanager.response;

import lombok.Data;

@Data
public class JwtAuthResponse {

    private String message;
    private String token;

    public JwtAuthResponse(String message, String token) {
        this.message = message;
        this.token = token;
    }
}
