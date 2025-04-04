package org.sorokovsky.jwtauth.strategy;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.contract.Token;
import org.sorokovsky.jwtauth.deserializer.TokenDeserializer;
import org.sorokovsky.jwtauth.serializer.TokenSerializer;

import java.time.temporal.ChronoUnit;
import java.util.Arrays;

@RequiredArgsConstructor
@Setter
@AllArgsConstructor
public class CookieRefreshTokenStorageStrategy implements TokenStorageStrategy {
    private final TokenSerializer serializer;
    private final TokenDeserializer deserializer;
    private String cookieName = "refresh-token";

    @Override
    public Token get(HttpServletRequest request) {
        final var cookies = request.getCookies();
        if (cookies == null) return null;
        final var rawToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(cookieName))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
        return deserializer.apply(rawToken);
    }

    @Override
    public void set(HttpServletResponse response, Token token) {
        final var maxAge = (int) ChronoUnit.SECONDS.between(token.createdAt(), token.expiresAt());
        response.addCookie(generateCookie(serializer.apply(token), maxAge));
    }

    @Override
    public void clear(HttpServletResponse response) {
        response.addCookie(generateCookie(null, 0));
    }

    private Cookie generateCookie(String token, int maxAge) {
        final var cookie = new Cookie(cookieName, token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setDomain(null);
        cookie.setMaxAge(maxAge);
        return cookie;
    }
}
