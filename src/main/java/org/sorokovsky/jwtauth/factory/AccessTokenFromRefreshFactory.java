package org.sorokovsky.jwtauth.factory;

import lombok.Data;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

@Component
@Data
public class AccessTokenFromRefreshFactory implements Function<TokenModel, TokenModel> {
    private Duration lifetime = Duration.ofMinutes(15);

    @Override
    public TokenModel apply(TokenModel tokenModel) {
        var now = Instant.now();
        return new TokenModel(UUID.randomUUID(), tokenModel.email(), now, now.plus(lifetime));
    }
}
