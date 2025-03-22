package org.sorokovsky.jwtauth.factory;

import lombok.Setter;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

@Setter
public class RefreshTokenFactory implements Function<Authentication, TokenModel> {
    private Duration tokenLifetime = Duration.ofDays(7);

    @Override
    public TokenModel apply(Authentication authentication) {
        var now = Instant.now();
        return new TokenModel(UUID.randomUUID(), authentication.getName(), now, now.plus(tokenLifetime));
    }
}
