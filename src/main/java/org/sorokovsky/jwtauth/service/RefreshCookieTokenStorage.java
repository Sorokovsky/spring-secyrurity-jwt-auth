package org.sorokovsky.jwtauth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class RefreshCookieTokenStorage {
    private static final String COOKIE_NAME = "__Host-refresh-token";

    public void set(String token, int lifetime, HttpServletResponse response) {
        var cookie = new Cookie(COOKIE_NAME, token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(lifetime);
        cookie.setDomain(null);
        response.addCookie(cookie);
    }

    public String get(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(COOKIE_NAME))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }
}
