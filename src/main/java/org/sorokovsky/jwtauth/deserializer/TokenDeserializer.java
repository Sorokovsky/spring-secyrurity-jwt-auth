package org.sorokovsky.jwtauth.deserializer;

import org.sorokovsky.jwtauth.contract.Token;

import java.util.function.Function;

public interface TokenDeserializer extends Function<String, Token> {
}
