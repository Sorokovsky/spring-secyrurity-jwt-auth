package org.sorokovsky.jwtauth.strategy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.sorokovsky.jwtauth.service.AccessBearerTokenStorage;
import org.sorokovsky.jwtauth.service.RefreshCookieTokenStorage;
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
    private Function<Authentication, TokenModel> accessTokenFactory;
    private Function<Authentication, TokenModel> refreshTokenFactory;
    private Function<TokenModel, String> accessTokenSerializer;
    private Function<TokenModel, String> refreshTokenSerializer;
    private RefreshCookieTokenStorage cookieTokenStorage;
    private AccessBearerTokenStorage bearerTokenStorage;

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            var accessToken = accessTokenFactory.apply(authentication);
            var refreshToken = refreshTokenFactory.apply(authentication);
            var lifetime = (int) ChronoUnit.SECONDS.between(refreshToken.createdAt(), refreshToken.expiresAt());
            cookieTokenStorage.set(refreshTokenSerializer.apply(refreshToken), lifetime, response);
            bearerTokenStorage.set(accessTokenSerializer.apply(accessToken), response);
        }
    }
}
