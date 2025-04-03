package org.sorokovsky.jwtauth.serializer;

import org.sorokovsky.jwtauth.contract.Token;

import java.util.function.Function;

public interface TokenSerializer extends Function<Token, String> {
}
