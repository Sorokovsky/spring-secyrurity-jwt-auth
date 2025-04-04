package org.sorokovsky.jwtauth.service;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.contract.LoginUser;
import org.sorokovsky.jwtauth.contract.RegisterUser;
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

    public User register(RegisterUser user, HttpServletResponse response) {
        final var loginUser = new LoginUser(user.email(), user.password());
        final var exists = repository.existsByEmail(loginUser.email());
        if (!exists) throw new UsernameNotFoundException(loginUser.email());
        var createdUser = repository.save(new User(loginUser.email(), passwordEncoder.encode(loginUser.password())));
        authenticate(loginUser, response);
        return createdUser;
    }

    public void login(LoginUser user, HttpServletResponse response) {
        final var candidate = repository.findByEmail(user.email()).orElse(null);
        if (candidate == null) throw new UsernameNotFoundException(user.email());
        if (!passwordEncoder.matches(user.password(), candidate.getPassword()))
            throw new IllegalArgumentException("Passwords do not match");
        authenticate(user, response);
    }

    private void authenticate(LoginUser user, HttpServletResponse response) {
        var authRequest = UsernamePasswordAuthenticationToken.unauthenticated(user.email(), user.password());
        var authResponse = authenticationManager.authenticate(authRequest);
        System.out.println(authResponse);
        SecurityContextHolder.getContext().setAuthentication(authResponse);
        final var refreshToken = refreshTokenFactory.apply(authResponse);
        final var accessToken = accessTokenFactory.apply(refreshToken);
        bearerAccessTokenStorageStrategy.set(response, accessToken);
        cookieRefreshTokenStorageStrategy.set(response, refreshToken);
    }
}
