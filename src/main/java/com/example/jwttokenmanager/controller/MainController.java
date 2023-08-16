package com.example.jwttokenmanager.controller;

import com.example.jwttokenmanager.helper.JwtTokenHelper;
import com.example.jwttokenmanager.payload.JwtAuthRequestPayload;
import com.example.jwttokenmanager.payload.JwtValidationRequestPayload;
import com.example.jwttokenmanager.response.JwtValidationResponse;
import com.example.jwttokenmanager.response.JwtAuthResponse;
import com.example.jwttokenmanager.service.AdminTokenAuthenticator;
import com.example.jwttokenmanager.service.RequestTokenAuthenticator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@RestController
public class MainController {

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RequestTokenAuthenticator requestTokenAuthenticator;

    @Autowired
    private AdminTokenAuthenticator adminTokenAuthenticator;

    @PostMapping("/auth/token")
    public ResponseEntity<JwtAuthResponse> getToken(@RequestBody JwtAuthRequestPayload requestPayload) {

        boolean isAuthenticated = requestTokenAuthenticator.authenticate(
                requestPayload.getUsername(),
                requestPayload.getPassword()
        );

        if (isAuthenticated) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(requestPayload.getUsername());
            String token = jwtTokenHelper.generateToken(userDetails);
            return new ResponseEntity<>(new JwtAuthResponse(
                "Token generated successfully",
                token
            ), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new JwtAuthResponse(
                "Token generation failed",
                null
            ), HttpStatus.I_AM_A_TEAPOT);
        }
    }

    @PostMapping("/auth/validate")
    public ResponseEntity<JwtValidationResponse> validateToken(@RequestBody JwtValidationRequestPayload requestPayload, @RequestHeader("Authorization") String token) {

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        UserDetails userDetails = userDetailsService.loadUserByUsername(requestPayload.getUsername());
        boolean valid = jwtTokenHelper.validateToken(request, token, userDetails);
        if (valid) {
            return new ResponseEntity<>(new JwtValidationResponse(
                    "Validation successful",
                    true
            ), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new JwtValidationResponse(
                    "Validation failed",
                    false
            ), HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/admin/validate")
    public ResponseEntity<JwtValidationResponse> validateIfUserIsAdmin(@RequestHeader("Authorization") String token) {
        try {
            if (adminTokenAuthenticator.validateAdminToken(token)) {
                return new ResponseEntity<>(new JwtValidationResponse(
                        "Validation complete",
                        true
                ), HttpStatus.OK);
            }
            else {
                return new ResponseEntity<>(new JwtValidationResponse(
                        "Validation failed",
                        false
                ), HttpStatus.UNAUTHORIZED);
            }
        } catch(Exception e) {
            return new ResponseEntity<>(new JwtValidationResponse(
                    "Validation failed - " + e.getMessage(),
                    false
            ), HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/auth/revoke")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token) {

        try {
            if (token.startsWith("Bearer") && jwtTokenHelper.revokeToken(token.substring(7))) {
                return new ResponseEntity<>(Map.of("message", "Logged out"), HttpStatus.OK);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        return new ResponseEntity<>(Map.of("message", "Failed to log out"), HttpStatus.FORBIDDEN);
    }
}
