package org.sorokovsky.jwtauth.factory;

import org.sorokovsky.jwtauth.contract.Token;

import java.util.function.Function;

public interface RecreateTokenFactory extends Function<Token, Token> {
}
