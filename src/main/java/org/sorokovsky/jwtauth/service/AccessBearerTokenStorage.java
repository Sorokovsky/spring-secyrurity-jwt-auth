package org.sorokovsky.jwtauth.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;

public class AccessBearerTokenStorage {
    private static final String BEARER_PREFIX = "Bearer ";

    public void set(String token, HttpServletResponse response) {
        response.addHeader(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + token);
    }

    public String get(HttpServletRequest request) {
        var header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
