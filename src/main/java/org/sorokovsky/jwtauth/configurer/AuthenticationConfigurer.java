package org.sorokovsky.jwtauth.configurer;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.converter.JwtConverter;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;

import java.util.function.Function;

@AllArgsConstructor
@NoArgsConstructor
@Setter
public class AuthenticationConfigurer extends AbstractHttpConfigurer<AuthenticationConfigurer, HttpSecurity> {
    private Function<String, TokenModel> accessTokenDeserializer;
    private Function<String, TokenModel> refreshTokenDeserializer;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var filter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class),
                new JwtConverter(accessTokenDeserializer, refreshTokenDeserializer));
        filter.setSuccessHandler((request, response, authentication) -> {
        });
        filter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(new Http403ForbiddenEntryPoint()));
        var authProvider = new PreAuthenticatedAuthenticationProvider();
        builder.addFilterAfter(filter, CsrfFilter.class);
    }
}
