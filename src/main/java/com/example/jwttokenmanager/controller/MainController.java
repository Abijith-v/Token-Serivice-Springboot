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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
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
            // Set response
            JwtAuthResponse response = new JwtAuthResponse();
            response.setToken(token);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new JwtAuthResponse(), HttpStatus.I_AM_A_TEAPOT);
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

    @PostMapping("/admin/validate")
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
}
