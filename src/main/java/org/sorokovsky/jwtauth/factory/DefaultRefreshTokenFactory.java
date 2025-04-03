package org.sorokovsky.jwtauth.factory;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.contract.Token;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Component
public class DefaultRefreshTokenFactory implements RefreshTokenFactory {
    private Duration tokenLifetime = Duration.ofDays(7);

    @Override
    public Token apply(Authentication authentication) {
        final var now = Instant.now();
        return new Token(UUID.randomUUID(), authentication.getName(), now, now.plus(tokenLifetime));
    }
}
