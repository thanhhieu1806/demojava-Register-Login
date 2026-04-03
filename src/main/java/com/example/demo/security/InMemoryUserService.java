package com.example.demo.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class InMemoryUserService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();

    public InMemoryUserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        createUserInternal("admin", "admin123", "admin@example.com", Set.of("ADMIN"));
        createUserInternal("user", "user123", "user@example.com", Set.of("USER"));
    }

    public void registerUser(String username, String rawPassword, String email) {
        String normalized = normalize(username);
        if (normalized == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tên đăng nhập không hợp lệ");
        }
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Mật khẩu không hợp lệ");
        }
        if (!isValidEmail(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email không hợp lệ");
        }
        if ("admin".equalsIgnoreCase(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tên đăng nhập đã tồn tại");
        }
        UserRecord newUser = new UserRecord(
                normalized,
                passwordEncoder.encode(rawPassword),
                email.trim(),
                Set.of("USER")
        );
        UserRecord existing = users.putIfAbsent(normalized, newUser);
        if (existing != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tên đăng nhập đã tồn tại");
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String normalized = normalize(username);
        if (normalized == null) {
            throw new UsernameNotFoundException("User not found");
        }
        UserRecord record = users.get(normalized);
        if (record == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return User.builder()
                .username(record.username())
                .password(record.passwordHash())
                .roles(record.roles().toArray(new String[0]))
                .build();
    }

    private void createUserInternal(String username, String rawPassword, String email, Set<String> roles) {
        UserRecord record = new UserRecord(
                username,
                passwordEncoder.encode(rawPassword),
                email,
                roles
        );
        users.put(username, record);
    }

    private String normalize(String username) {
        if (username == null) {
            return null;
        }
        String normalized = username.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private record UserRecord(String username, String passwordHash, String email, Set<String> roles) {
    }

    private boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        String trimmed = email.trim();
        int at = trimmed.indexOf('@');
        if (at <= 0 || at == trimmed.length() - 1) {
            return false;
        }
        return trimmed.indexOf('.', at) > at + 1;
    }
}
