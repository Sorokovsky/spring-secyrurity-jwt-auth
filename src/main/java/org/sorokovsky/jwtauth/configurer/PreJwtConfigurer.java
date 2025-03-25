package org.sorokovsky.jwtauth.configurer;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.filter.JwtFilter;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.sorokovsky.jwtauth.service.AccessBearerTokenStorage;
import org.sorokovsky.jwtauth.service.RefreshCookieTokenStorage;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.session.DisableEncodeUrlFilter;

import java.util.function.Function;

@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PreJwtConfigurer extends AbstractHttpConfigurer<PreJwtConfigurer, HttpSecurity> {
    private Function<String, TokenModel> refreshTokenDeserializer;
    private Function<String, TokenModel> accessTokenDeserializer;
    private Function<TokenModel, TokenModel> fromRefreshToAccessFactory;
    private Function<TokenModel, String> accessTokenSerializer;
    private AccessBearerTokenStorage accessBearerTokenStorage;
    private RefreshCookieTokenStorage refreshCookieTokenStorage;


    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) {
        var filter = new JwtFilter(refreshTokenDeserializer, accessTokenDeserializer, fromRefreshToAccessFactory, accessTokenSerializer, accessBearerTokenStorage, refreshCookieTokenStorage);
        builder.addFilterAfter(filter, DisableEncodeUrlFilter.class);
    }
}
