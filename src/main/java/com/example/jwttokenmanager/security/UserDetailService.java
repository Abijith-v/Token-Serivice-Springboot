package com.example.jwttokenmanager.security;

import com.example.jwttokenmanager.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // Over rider loadUserByUsername so that spring will load using email
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // Load using email
        return userRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email - " + email));
    }
}
