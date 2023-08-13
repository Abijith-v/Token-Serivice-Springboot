package com.example.jwttokenmanager.security;

import com.example.jwttokenmanager.model.Role;
import com.example.jwttokenmanager.model.Users;
import com.example.jwttokenmanager.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
public class UserDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // Over rider loadUserByUsername so that spring will load using email
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // Load using email
        Users user = userRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email - " + email));

        return new User(user.getUsername(), user.getPassword(), getGrantedAuthorities(user.getRoles()));
    }

    private List<GrantedAuthority> getGrantedAuthorities(Set<Role> privileges) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (Role role : privileges) {
            authorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        }
        System.out.println(authorities);
        return authorities;
    }
}
