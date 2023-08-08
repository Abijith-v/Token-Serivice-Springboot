package com.example.jwttokenmanager.helper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenHelper {

    public static final long TOKEN_VALIDITY = 18000;

    private static final String SECRET = "mySecret";

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
        Map<String, Object> claims = new HashMap<>();
        return performTokenGeneration(claims, userDetails.getUsername());
    }

    private String performTokenGeneration(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
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
}
