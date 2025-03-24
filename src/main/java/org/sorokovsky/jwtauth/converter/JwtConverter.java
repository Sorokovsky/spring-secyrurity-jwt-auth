package org.sorokovsky.jwtauth.converter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Function;

@AllArgsConstructor
@NoArgsConstructor
@Setter
public class JwtConverter implements AuthenticationConverter {
    private static final String BEARER_PREFIX = "Bearer ";
    private Function<String, TokenModel> accessTokenDeserializer;

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            var rawAccessToken = authorization.substring(BEARER_PREFIX.length());
            var accessToken = accessTokenDeserializer.apply(rawAccessToken);
            if (accessToken != null) {
                return new PreAuthenticatedAuthenticationToken(accessToken, rawAccessToken);
            }
        }
        return null;
    }
}
