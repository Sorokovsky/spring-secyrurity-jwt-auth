package org.sorokovsky.jwtauth.service;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.entity.User;
import org.sorokovsky.jwtauth.factory.DefaultAccessTokenFactory;
import org.sorokovsky.jwtauth.factory.DefaultRefreshTokenFactory;
import org.sorokovsky.jwtauth.repository.UsersRepository;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.sorokovsky.jwtauth.strategy.CookieRefreshTokenStorageStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy;
    private final CookieRefreshTokenStorageStrategy cookieRefreshTokenStorageStrategy;
    private final DefaultAccessTokenFactory accessTokenFactory;
    private final DefaultRefreshTokenFactory refreshTokenFactory;
    private final UsersRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public User register(User user, HttpServletResponse response) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        final var exists = repository.existsByEmail(user.getEmail());
        if (!exists) throw new UsernameNotFoundException(user.getEmail());
        var createdUser = repository.save(user);
        authenticate(createdUser, response);
        return createdUser;
    }

    public void login(User user, HttpServletResponse response) {
        final var candidate = repository.findByEmail(user.getEmail()).orElse(null);
        if (candidate == null) throw new UsernameNotFoundException(user.getEmail());
        if (!passwordEncoder.matches(user.getPassword(), candidate.getPassword()))
            throw new IllegalArgumentException("Passwords do not match");
        authenticate(candidate, response);
    }

    private void authenticate(User user, HttpServletResponse response) {
        var authRequest = UsernamePasswordAuthenticationToken.unauthenticated(user.getEmail(), user.getPassword());
        var authResponse = authenticationManager.authenticate(authRequest);
        SecurityContextHolder.getContext().setAuthentication(authResponse);
        final var refreshToken = refreshTokenFactory.apply(authResponse);
        final var accessToken = accessTokenFactory.apply(refreshToken);
        bearerAccessTokenStorageStrategy.set(response, accessToken);
        cookieRefreshTokenStorageStrategy.set(response, refreshToken);
    }
}
