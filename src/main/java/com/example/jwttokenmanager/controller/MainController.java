package com.example.jwttokenmanager.controller;

import com.example.jwttokenmanager.helper.JwtTokenHelper;
import com.example.jwttokenmanager.payload.JwtAuthRequestPayload;
import com.example.jwttokenmanager.payload.JwtValidationRequestPayload;
import com.example.jwttokenmanager.response.JwtValidationResponse;
import com.example.jwttokenmanager.response.JwtAuthResponse;
import com.example.jwttokenmanager.service.RequestTokenAuthenticator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@RestController
public class MainController {

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RequestTokenAuthenticator requestTokenAuthenticator;

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

    @PostMapping("auth/validate")
    public ResponseEntity<JwtValidationResponse> validateToken(@RequestBody JwtValidationRequestPayload requestPayload, @RequestHeader("Authorization") String token) {

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        UserDetails userDetails = userDetailsService.loadUserByUsername(requestPayload.getUsername());

        return new ResponseEntity<>(new JwtValidationResponse(
            "Validation complete",
            jwtTokenHelper.validateToken(request, token, userDetails)
        ), HttpStatus.OK);
    }
}
