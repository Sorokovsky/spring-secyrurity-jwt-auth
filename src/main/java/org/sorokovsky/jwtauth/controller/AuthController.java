package org.sorokovsky.jwtauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.contract.LoginUser;
import org.sorokovsky.jwtauth.contract.RegisterUser;
import org.sorokovsky.jwtauth.entity.UserEntity;
import org.sorokovsky.jwtauth.repository.UsersRepository;
import org.sorokovsky.jwtauth.strategy.AuthenticationHttpStrategy;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationHttpStrategy authenticationHttpStrategy;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUser registerUser) {
        var existsCandidate = usersRepository.existsByEmail(registerUser.email());
        if (existsCandidate) return ResponseEntity.badRequest().body("Email already exists");
        var user = new UserEntity(registerUser.email(), registerUser.password());
        usersRepository.save(user);
        var authToken = new UsernamePasswordAuthenticationToken(registerUser.email(), registerUser.password());
        authenticationManager.authenticate(authToken);
        return ResponseEntity.ok().body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginUser loginUser, HttpServletRequest request, HttpServletResponse response) {
        var user = usersRepository.findByEmail(loginUser.email()).orElse(null);
        if (user == null) return ResponseEntity.notFound().build();
        var correctPassword = passwordEncoder.matches(loginUser.password(), user.getPassword());
        if (!correctPassword) return ResponseEntity.badRequest().body("Incorrect password");
        var authToken = new UsernamePasswordAuthenticationToken(loginUser.email(), loginUser.password());
        var authentication = authenticationManager.authenticate(authToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        authenticationHttpStrategy.onAuthentication(authentication, request, response);
        return ResponseEntity.ok().body(user);
    }
}
