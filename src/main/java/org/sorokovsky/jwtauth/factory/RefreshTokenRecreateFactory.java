package org.sorokovsky.jwtauth.factory;

import lombok.Setter;
import org.sorokovsky.jwtauth.contract.Token;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Component
@Setter
public class RefreshTokenRecreateFactory implements RecreateTokenFactory {
    private Duration lifetime = Duration.ofDays(7);

    @Override
    public Token apply(Token token) {
        final var now = Instant.now();
        return new Token(UUID.randomUUID(), token.email(), now, now.plus(lifetime));
    }
}
