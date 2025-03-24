package org.sorokovsky.jwtauth.configurer;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.sorokovsky.jwtauth.converter.JwtConverter;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.csrf.CsrfFilter;

import java.util.function.Function;

@AllArgsConstructor
@NoArgsConstructor
@Setter
public class AuthenticationConfigurer extends AbstractHttpConfigurer<AuthenticationConfigurer, HttpSecurity> {
    private Function<String, TokenModel> accessTokenDeserializer;
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) {
        var filter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class),
                new JwtConverter(accessTokenDeserializer));
        filter.setSuccessHandler((request, response, authentication) -> {
        });
        filter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(new Http403ForbiddenEntryPoint()));
        var authProvider = new PreAuthenticatedAuthenticationProvider();
        authProvider.setPreAuthenticatedUserDetailsService(authenticationUserDetailsService);
        builder.addFilterAfter(filter, CsrfFilter.class);
    }
}
