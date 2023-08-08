package com.example.jwttokenmanager.response;

import lombok.Data;

@Data
public class JwtValidationResponse {

    String message;
    boolean tokenValid;

    public JwtValidationResponse(String message, boolean tokenValid) {
        this.message = message;
        this.tokenValid = tokenValid;
    }

}
