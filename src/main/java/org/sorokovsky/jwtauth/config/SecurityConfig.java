package org.sorokovsky.jwtauth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.sorokovsky.jwtauth.configurer.AuthenticationConfigurer;
import org.sorokovsky.jwtauth.deserializer.AccessTokenDeserializer;
import org.sorokovsky.jwtauth.factory.AccessTokenFactory;
import org.sorokovsky.jwtauth.factory.RefreshTokenFactory;
import org.sorokovsky.jwtauth.serializer.AccessTokenSerializer;
import org.sorokovsky.jwtauth.serializer.RefreshTokenSerializer;
import org.sorokovsky.jwtauth.service.BearerAuthenticationService;
import org.sorokovsky.jwtauth.service.RefreshCookieTokenStorage;
import org.sorokovsky.jwtauth.strategy.AuthenticationHttpStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

import java.util.Base64;

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
        //noinspection removal
        http.apply(jwtConfigurer);
        return http
                .authorizeHttpRequests(x -> {
                    x.requestMatchers("/v3/**", "/swagger-ui/**").permitAll();
                    x.anyRequest().authenticated();
                })
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(x ->
                        x.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
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
    public AccessTokenDeserializer accessTokenDeserializer(
            @Value("{jwt.access-token-key:}") String accessTokenKey
    ) throws JOSEException {
        return new AccessTokenDeserializer(new MACVerifier(
                new OctetSequenceKey.Builder(Base64.getDecoder().decode(accessTokenKey)).build()
        ));
    }

    @Bean
    public AccessTokenSerializer accessTokenSerializer(@Value("{jwt.access-token-key:}") String accessTokenKey) throws KeyLengthException {
        return new AccessTokenSerializer(new MACSigner(
                new OctetSequenceKey.Builder(Base64.getDecoder().decode(accessTokenKey)).build()
        ));
    }

    @Bean
    public RefreshTokenSerializer refreshTokenSerializer(@Value("{jwt.refresh-token-key:}") String refreshTokenKey) throws KeyLengthException {
        return new RefreshTokenSerializer(
                new DirectEncrypter(
                        new OctetSequenceKey.Builder(Base64.getDecoder().decode(refreshTokenKey)).build()
                )
        );
    }

    @Bean
    public AuthenticationHttpStrategy authenticationHttpStrategy(AccessTokenSerializer accessTokenSerializer,
                                                                 RefreshTokenSerializer refreshTokenSerializer) {
        return new AuthenticationHttpStrategy(new AccessTokenFactory(), new RefreshTokenFactory(),
                accessTokenSerializer, refreshTokenSerializer, new RefreshCookieTokenStorage());
    }
}
