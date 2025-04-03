package org.sorokovsky.jwtauth.factory;

import org.sorokovsky.jwtauth.contract.Token;
import org.springframework.security.core.Authentication;

import java.util.function.Function;

public interface RefreshTokenFactory extends Function<Authentication, Token> {
}
