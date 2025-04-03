package org.sorokovsky.jwtauth.strategy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.sorokovsky.jwtauth.contract.Token;

public interface TokenStorageStrategy {
    Token get(HttpServletRequest request);

    void set(HttpServletResponse response, Token token);

    void clear(HttpServletResponse response);
}
