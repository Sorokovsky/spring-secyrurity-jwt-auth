package org.sorokovsky.jwtauth.converter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class BearerAuthenticationConverter implements AuthenticationConverter {
    private final BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy;

    @Override
    public Authentication convert(HttpServletRequest request) {
        final var accessToken = bearerAccessTokenStorageStrategy.get(request);
        if (accessToken == null) return null;
        return new PreAuthenticatedAuthenticationToken(accessToken, accessToken);
    }
}
