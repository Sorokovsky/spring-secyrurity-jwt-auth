package org.sorokovsky.jwtauth.converter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class BearerAuthenticationConverter implements AuthenticationConverter {
    private final BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication convert(HttpServletRequest request) {
        final var accessToken = bearerAccessTokenStorageStrategy.get(request);
        if (accessToken == null) return null;
        return new UsernamePasswordAuthenticationToken(accessToken.email(), null);
    }
}
