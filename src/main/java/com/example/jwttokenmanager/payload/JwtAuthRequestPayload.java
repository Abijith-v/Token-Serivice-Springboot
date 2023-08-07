package com.example.jwttokenmanager.payload;

import lombok.Data;

@Data
public class JwtAuthRequestPayload {

    private String username;
    private String password;
}
