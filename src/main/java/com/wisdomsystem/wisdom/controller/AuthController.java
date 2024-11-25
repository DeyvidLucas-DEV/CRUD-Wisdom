package com.wisdomsystem.wisdom.controller;


import com.wisdomsystem.wisdom.config.WebSecurityConfig;
import com.wisdomsystem.wisdom.dto.AuthRequest;
import com.wisdomsystem.wisdom.dto.AuthResponse;
import com.wisdomsystem.wisdom.model.User;
import com.wisdomsystem.wisdom.repository.UserRepository;
import com.wisdomsystem.wisdom.security.JwtTokenUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserRepository userRepository;
    private final WebSecurityConfig webSecurityConfig;

    public AuthController(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil, UserRepository userRepository, WebSecurityConfig webSecurityConfig) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
        this.webSecurityConfig = webSecurityConfig;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtTokenUtil.generateToken(userDetails.getUsername());

        return new AuthResponse(token);
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthRequest request) {
        // Verifica se o usuário já existe
        Optional<User> existingUser = userRepository.findByUsername(request.getUsername());
        if (existingUser.isPresent()) {
            return ResponseEntity.badRequest().body("Usuário já existe.");
        }

        // Criptografa a senha
        String encryptedPassword = webSecurityConfig.passwordEncoder().encode(request.getPassword());

        // Cria um novo usuário
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(encryptedPassword);
        newUser.setRole("USER"); // Define o papel padrão

        // Salva no banco de dados
        userRepository.save(newUser);

        return ResponseEntity.ok("Usuário registrado com sucesso.");
    }
}
