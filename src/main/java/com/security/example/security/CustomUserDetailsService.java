package com.security.example.security;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private List<UserDetails> users = List.of(
            User.withUsername("admin")
                    .password("{noop}adminpass") // "{noop}" tells Spring to use a plaintext password encoder
                    .roles("ADMIN")
                    .build(),
            User.withUsername("user")
                    .password("{noop}userpass")
                    .roles("USER")
                    .build()
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}