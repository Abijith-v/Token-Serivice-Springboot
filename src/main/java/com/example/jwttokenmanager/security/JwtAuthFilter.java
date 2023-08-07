package com.example.jwttokenmanager.security;

import com.example.jwttokenmanager.helper.JwtTokenHelper;
import jakarta.security.auth.message.AuthException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Get token, token looks like Bearer 214214....
//        String tokenFromRequest = request.getHeader("Authorization");
//        String token = null, username = null;
//
//        // Check if token starts with Bearer
//        if (tokenFromRequest != null && tokenFromRequest.startsWith("Bearer")) {
//            token = tokenFromRequest.substring(7);
//            try {
//                // Fetch username
//                username = jwtTokenHelper.getUsernameFromToken(token);
//            } catch (Exception e) {
//                System.out.println("Unable to generate JWT token - " + e.getMessage());
//            }
//
//            // Validate the token
//            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                // Fetch UserDetails using username
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                if (jwtTokenHelper.validateToken(token, userDetails)) {
//                    // Perform authentication
//                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//                        userDetails,
//                        userDetails.getAuthorities()
//                    );
//                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//                } else {
//                    System.out.println("Invalid JWT token");
//                }
//            }
//        } else {
//            System.out.println("Auth not of Bearer");
//        }
//
//        // At the end call do filter. If there are some issues in token, it will hit any one of the print statement
//        // Then control will be forwarded to JwtEntryPoint class and error will be thrown from there
        filterChain.doFilter(request, response);
    }
}
