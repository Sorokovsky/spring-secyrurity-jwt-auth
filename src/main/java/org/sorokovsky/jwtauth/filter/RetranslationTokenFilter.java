package org.sorokovsky.jwtauth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.strategy.TokenStorageStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class RetranslationTokenFilter extends OncePerRequestFilter {
    private final TokenStorageStrategy tokenStorageStrategy;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = tokenStorageStrategy.get(request);
        if (token != null) {
            tokenStorageStrategy.set(response, token);
        }
        filterChain.doFilter(request, response);
    }
}
