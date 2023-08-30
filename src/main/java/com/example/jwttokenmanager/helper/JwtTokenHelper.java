package com.example.jwttokenmanager.helper;

import com.example.jwttokenmanager.model.BlacklistedToken;
import com.example.jwttokenmanager.repository.BlacklistedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenHelper {

    public static final long TOKEN_VALIDITY = 1200; // 20 minutes

    public static final String SECRET = "mySecret";

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction) {
        Claims claims = getAllClaimsFromToken(token);
        return claimsTFunction.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        Date expirationDate = getExpirationDateFromToken(token);
        return expirationDate.before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return performTokenGeneration(roles, userDetails.getUsername());
    }

    private String performTokenGeneration(List<String> roles, String subject) {

//        System.out.println("performTokenGeneration - " + role + " -> " + allRoles.getOrDefault(role, "NORMAL"));
        return Jwts.builder()
                .claim("roles", roles)//allRoles.getOrDefault(role, "NORMAL"))
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, SECRET).compact();
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public boolean validateToken(HttpServletRequest request, String tokenFromRequest, UserDetails userDetails) {

        String token = null, username = null;

        // Check if token starts with Bearer
        if (tokenFromRequest != null && tokenFromRequest.startsWith("Bearer")) {
            token = tokenFromRequest.substring(7);
            try {
                // Check if token is blacklisted
                if (blacklistedTokenRepository.findByToken(token) != null) {
                    System.out.println("Token is blacklisted");
                    return false;
                }
                // Fetch username
                username = getUsernameFromToken(token);
            } catch (Exception e) {
                System.out.println("Unable to generate JWT token - " + e.getMessage());
            }

            // Validate the token
            if (username != null && SecurityContextHolder.getContext().getAuthentication() != null) {
                // Fetch UserDetails using username
                if (validateTokenUsernameAndExpiry(token, userDetails.getUsername())) {
                    // Perform authentication
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            userDetails.getAuthorities()
                    );
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                    // Token is validated
                    return true;
                } else {
                    System.out.println("Invalid JWT token");
                }
            }
        } else {
            System.out.println("Auth not of Bearer");
        }

        return false;
    }

    private boolean validateTokenUsernameAndExpiry(String token, String username) {
        String usernameFromToken = getUsernameFromToken(token);
        return usernameFromToken.equals(username) && !isTokenExpired(token);
    }

    public boolean revokeToken(String token) {
        System.out.println(token);
        if (getUsernameFromToken(token) != null) {
            BlacklistedToken blacklistedToken = new BlacklistedToken();
            blacklistedToken.setToken(token);
            BlacklistedToken savedBlacklistedToken = blacklistedTokenRepository.save(blacklistedToken);
            return savedBlacklistedToken.getId() != null;
        } else {
            return false;
        }
    }
}
