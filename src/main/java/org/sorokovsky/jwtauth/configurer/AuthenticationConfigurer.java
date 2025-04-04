package org.sorokovsky.jwtauth.configurer;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sorokovsky.jwtauth.contract.ApiError;
import org.sorokovsky.jwtauth.converter.BearerAuthenticationConverter;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationConfigurer implements SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationConfigurer.class);

    private BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy;
    private AuthenticationEntryPoint authenticationEntryPoint = (request, response, authException) -> {
        LOGGER.error(authException.getMessage());
        final var apiError = new ApiError("Unauthorized", HttpStatus.UNAUTHORIZED.value());
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        response.sendError(apiError.status());
    };

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.exceptionHandling(config -> config
                .authenticationEntryPoint(authenticationEntryPoint));
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        final var authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        final var converter = new BearerAuthenticationConverter(bearerAccessTokenStorageStrategy);
        final var authenticationFilter = new AuthenticationFilter(authenticationManager, converter);
        authenticationFilter.setSuccessHandler((request, response, authentication) -> {
        });
        authenticationFilter.setFailureHandler(new AuthenticationEntryPointFailureHandler(authenticationEntryPoint));
        builder.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    public AuthenticationConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    public AuthenticationConfigurer bearerAccessTokenStorageStrategy(BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy) {
        this.bearerAccessTokenStorageStrategy = bearerAccessTokenStorageStrategy;
        return this;
    }
}
