package org.sorokovsky.jwtauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.contract.GetUser;
import org.sorokovsky.jwtauth.contract.LoginUser;
import org.sorokovsky.jwtauth.contract.RegisterUser;
import org.sorokovsky.jwtauth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUser registerUser, HttpServletResponse response) {
        final var createdUser = authService.register(registerUser, response);
        final var getUserDto = new GetUser(createdUser.getId(), createdUser.getEmail(), createdUser.getCreatedAt(), createdUser.getUpdatedAt());
        return ResponseEntity.ok(getUserDto);
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody LoginUser loginUser, HttpServletResponse response) {
        authService.login(loginUser, response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh-tokens")
    public ResponseEntity<Void> refreshTokens(HttpServletRequest request, HttpServletResponse response) {
        authService.refreshTokens(request, response);
        return ResponseEntity.noContent().build();
    }
}
