package org.sorokovsky.jwtauth.factory;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.contract.Token;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Component
public class DefaultAccessTokenFactory implements AccessTokenFactory {
    private Duration tokenLifetime;

    @Override
    public Token apply(Token token) {
        final var now = Instant.now();
        return new Token(UUID.randomUUID(), token.email(), now, now.plus(tokenLifetime));
    }
}
