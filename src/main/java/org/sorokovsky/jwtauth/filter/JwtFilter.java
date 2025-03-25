package org.sorokovsky.jwtauth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.sorokovsky.jwtauth.service.AccessBearerTokenStorage;
import org.sorokovsky.jwtauth.service.RefreshCookieTokenStorage;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.function.Function;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final Function<String, TokenModel> refreshTokenDeserializer;
    private final Function<String, TokenModel> accessTokenDeserializer;
    private final Function<TokenModel, TokenModel> fromRefreshToAccessFactory;
    private final Function<TokenModel, String> accessTokenSerializer;
    private final AccessBearerTokenStorage accessBearerTokenStorage;
    private final RefreshCookieTokenStorage refreshCookieTokenStorage;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var rawAccessToken = accessBearerTokenStorage.get(request);
        if (rawAccessToken != null) {
            var accessToken = accessTokenDeserializer.apply(rawAccessToken);
            if (accessToken != null) {
                accessBearerTokenStorage.set(rawAccessToken, response);
            }
        }
        var rawRefreshToken = refreshCookieTokenStorage.get(request);
        if (rawRefreshToken != null) {
            var refreshToken = refreshTokenDeserializer.apply(rawRefreshToken);
            if (refreshToken != null) {
                var newAccessToken = fromRefreshToAccessFactory.apply(refreshToken);
                var rawNewAccessToken = accessTokenSerializer.apply(newAccessToken);
                request.setAttribute(HttpHeaders.AUTHORIZATION, rawNewAccessToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
