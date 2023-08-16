package com.example.jwttokenmanager.repository;

import com.example.jwttokenmanager.model.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {

    public BlacklistedToken findByToken(String token);
}
