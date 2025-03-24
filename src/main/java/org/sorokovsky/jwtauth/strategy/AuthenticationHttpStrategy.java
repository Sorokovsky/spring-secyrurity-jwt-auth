package org.sorokovsky.jwtauth.strategy;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.time.temporal.ChronoUnit;
import java.util.function.Function;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationHttpStrategy implements SessionAuthenticationStrategy {
    private static final String COOKIE_NAME = "__Host-refresh-token";
    private static final String BEARER_TEMPLATE = "Bearer %s";

    private Function<Authentication, TokenModel> accessTokenFactory;
    private Function<Authentication, TokenModel> refreshTokenFactory;
    private Function<TokenModel, String> accessTokenSerializer;
    private Function<TokenModel, String> refreshTokenSerializer;

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            var accessToken = accessTokenFactory.apply(authentication);
            var refreshToken = refreshTokenFactory.apply(authentication);
            var cookie = new Cookie(COOKIE_NAME, refreshTokenSerializer.apply(refreshToken));
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(refreshToken.createdAt(), refreshToken.expiresAt()));
            cookie.setDomain(null);
            response.addCookie(cookie);
            response.addHeader(HttpHeaders.AUTHORIZATION, BEARER_TEMPLATE.formatted(accessToken));
        }
    }
}
