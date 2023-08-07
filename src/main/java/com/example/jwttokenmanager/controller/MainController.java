package com.example.jwttokenmanager.controller;

import com.example.jwttokenmanager.helper.JwtTokenHelper;
import com.example.jwttokenmanager.payload.JwtAuthRequestPayload;
import com.example.jwttokenmanager.security.JwtAuthResponse;
import com.example.jwttokenmanager.service.RequestTokenAuthenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

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
}
