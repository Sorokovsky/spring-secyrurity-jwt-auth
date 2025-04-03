package org.sorokovsky.jwtauth.strategy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.contract.Token;
import org.sorokovsky.jwtauth.deserializer.TokenDeserializer;
import org.sorokovsky.jwtauth.serializer.TokenSerializer;
import org.springframework.http.HttpHeaders;

@RequiredArgsConstructor
public class BearerAccessTokenStorageStrategy implements TokenStorageStrategy {
    private final TokenSerializer serializer;
    private final TokenDeserializer deserializer;

    @Override
    public Token get(HttpServletRequest request) {
        var rawToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (rawToken == null) rawToken = request.getParameter(HttpHeaders.AUTHORIZATION);
        return deserializer.apply(rawToken);
    }

    @Override
    public void set(HttpServletResponse response, Token token) {
        response.setHeader(HttpHeaders.AUTHORIZATION, serializer.apply(token));
    }

    @Override
    public void clear(HttpServletResponse response) {
        response.setHeader(HttpHeaders.AUTHORIZATION, null);
    }
}
