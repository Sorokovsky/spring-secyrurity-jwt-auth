package org.sorokovsky.jwtauth.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
        return ResponseEntity.ok(authService.register(registerUser, response));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginUser loginUser, HttpServletResponse response) {
        authService.login(loginUser, response);
        return ResponseEntity.noContent().build();
    }
}
