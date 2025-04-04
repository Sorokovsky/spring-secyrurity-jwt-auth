package org.sorokovsky.jwtauth.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.contract.LoginUser;
import org.sorokovsky.jwtauth.contract.RegisterUser;
import org.sorokovsky.jwtauth.entity.User;
import org.sorokovsky.jwtauth.exception.BadRequestException;
import org.sorokovsky.jwtauth.exception.ForbiddenException;
import org.sorokovsky.jwtauth.factory.AccessTokenFactory;
import org.sorokovsky.jwtauth.factory.RecreateTokenFactory;
import org.sorokovsky.jwtauth.factory.RefreshTokenFactory;
import org.sorokovsky.jwtauth.repository.UsersRepository;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.sorokovsky.jwtauth.strategy.CookieRefreshTokenStorageStrategy;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy;
    private final CookieRefreshTokenStorageStrategy cookieRefreshTokenStorageStrategy;
    private final RecreateTokenFactory recreateTokenFactory;
    private final AccessTokenFactory accessTokenFactory;
    private final RefreshTokenFactory refreshTokenFactory;
    private final UsersRepository repository;
    private final PasswordEncoder passwordEncoder;

    public User register(RegisterUser user, HttpServletResponse response) {
        final var loginUser = new LoginUser(user.email(), user.password());
        final var exists = repository.existsByEmail(loginUser.email());
        if (exists) throw new BadRequestException("Email already exists");
        var createdUser = repository.save(new User(loginUser.email(), passwordEncoder.encode(loginUser.password())));
        authenticate(loginUser, response);
        return createdUser;
    }

    public void login(LoginUser user, HttpServletResponse response) {
        final var exception = new BadRequestException("Invalid email or password");
        final var candidate = repository.findByEmail(user.email()).orElse(null);
        if (candidate == null) throw exception;
        if (!passwordEncoder.matches(user.password(), candidate.getPassword()))
            throw exception;
        authenticate(user, response);
    }

    public void refreshTokens(HttpServletRequest request, HttpServletResponse response) {
        var refreshToken = cookieRefreshTokenStorageStrategy.get(request);
        if (refreshToken == null) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Form");
            throw new ForbiddenException("Missing refresh token");
        }
        refreshToken = recreateTokenFactory.apply(refreshToken);
        final var accessToken = accessTokenFactory.apply(refreshToken);
        bearerAccessTokenStorageStrategy.set(response, accessToken);
        cookieRefreshTokenStorageStrategy.set(response, refreshToken);
    }

    private void authenticate(LoginUser user, HttpServletResponse response) {
        var authentication = UsernamePasswordAuthenticationToken.unauthenticated(user.email(), user.password());
        final var refreshToken = refreshTokenFactory.apply(authentication);
        final var accessToken = accessTokenFactory.apply(refreshToken);
        bearerAccessTokenStorageStrategy.set(response, accessToken);
        cookieRefreshTokenStorageStrategy.set(response, refreshToken);
    }
}
