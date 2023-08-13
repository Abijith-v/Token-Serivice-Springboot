package com.example.jwttokenmanager.service;

import com.example.jwttokenmanager.helper.JwtTokenHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AdminTokenAuthenticator {

    public boolean validateAdminToken(String token) {

        if (!token.startsWith("Bearer")) {
            return false;
        }

        Claims claims = Jwts.parser()
                .setSigningKey(JwtTokenHelper.SECRET)
                .parseClaimsJws(token.substring(7))
                .getBody();

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");
        return roles.get(0).trim().equals("ROLE_ADMIN");
    }
}
