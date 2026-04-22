package com.secureapp;

import com.secureapp.model.User;
import com.secureapp.repository.UserRepository;
import com.secureapp.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks UserService userService;

    @Test
    void register_success() {
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("hashed");

        User saved = new User();
        saved.setId(1L);
        saved.setUsername("alice");
        when(userRepository.save(any())).thenReturn(saved);

        User result = userService.register("alice", "alice@example.com", "password123");

        assertEquals("alice", result.getUsername());
        verify(passwordEncoder).encode("password123");
    }

    @Test
    void register_duplicateUsername_throws() {
        when(userRepository.existsByUsername("alice")).thenReturn(true);

        assertThrows(IllegalArgumentException.class,
            () -> userService.register("alice", "alice@example.com", "password123"));
    }

    @Test
    void loadUserByUsername_found() {
        User user = new User();
        user.setUsername("alice");
        user.setPassword("hashed");
        user.setRole(User.Role.USER);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        var details = userService.loadUserByUsername("alice");

        assertEquals("alice", details.getUsername());
    }

    @Test
    void loadUserByUsername_notFound_throws() {
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThrows(org.springframework.security.core.userdetails.UsernameNotFoundException.class,
            () -> userService.loadUserByUsername("ghost"));
    }
}
