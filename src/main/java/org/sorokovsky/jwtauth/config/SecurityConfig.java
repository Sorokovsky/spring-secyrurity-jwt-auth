package org.sorokovsky.jwtauth.config;

import org.sorokovsky.jwtauth.configurer.AuthenticationConfigurer;
import org.sorokovsky.jwtauth.deserializer.AccessTokenDeserializer;
import org.sorokovsky.jwtauth.factory.AccessTokenFactory;
import org.sorokovsky.jwtauth.factory.RefreshTokenFactory;
import org.sorokovsky.jwtauth.serializer.AccessTokenSerializer;
import org.sorokovsky.jwtauth.serializer.RefreshTokenSerializer;
import org.sorokovsky.jwtauth.service.AccessBearerTokenStorage;
import org.sorokovsky.jwtauth.service.BearerAuthenticationService;
import org.sorokovsky.jwtauth.service.RefreshCookieTokenStorage;
import org.sorokovsky.jwtauth.strategy.AuthenticationHttpStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            UserDetailsService userDetailsService,
            AccessTokenDeserializer accessTokenDeserializer,
            AuthenticationHttpStrategy authenticationHttpStrategy) throws Exception {
        var jwtConfigurer = new AuthenticationConfigurer();
        jwtConfigurer.setAuthenticationUserDetailsService(authenticationUserDetailsService(userDetailsService));
        jwtConfigurer.setAccessTokenDeserializer(accessTokenDeserializer);
        jwtConfigurer.setBearerTokenStorage(new AccessBearerTokenStorage());
        //noinspection removal
        http.apply(jwtConfigurer);
        return http
                .authorizeHttpRequests(x -> {
                    x.requestMatchers("/auth/register", "/auth/login", "/swagger-ui/**", "/v3/**").permitAll();
                    x.anyRequest().authenticated();
                })
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(x ->
                        x.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                .addSessionAuthenticationStrategy(authenticationHttpStrategy)
                )
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService(UserDetailsService userDetailsService) {
        return new BearerAuthenticationService(userDetailsService);
    }

    @Bean
    public AuthenticationHttpStrategy authenticationHttpStrategy(AccessTokenSerializer accessTokenSerializer,
                                                                 RefreshTokenSerializer refreshTokenSerializer) {
        return new AuthenticationHttpStrategy(new AccessTokenFactory(), new RefreshTokenFactory(),
                accessTokenSerializer, refreshTokenSerializer, new RefreshCookieTokenStorage(), new AccessBearerTokenStorage());
    }

    @Bean
    public AuthenticationManager authenticationManager(
            PasswordEncoder passwordEncoder,
            UserDetailsService userDetailsService
    ) {
        var provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return new ProviderManager(provider);
    }
}
