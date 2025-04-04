package org.sorokovsky.jwtauth.config;

import org.sorokovsky.jwtauth.configurer.AuthenticationConfigurer;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy,
            UserDetailsService userDetailsService
    ) throws Exception {
        http.apply(new AuthenticationConfigurer())
                .bearerAccessTokenStorageStrategy(bearerAccessTokenStorageStrategy)
                .userDetailsService(userDetailsService);
        return http
                .authorizeHttpRequests(config -> config
                        .requestMatchers("/auth/login", "/auth/register", "/auth/refresh-tokens", "/swagger-ui/**", "/v3/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(config -> config
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .build();
    }
}
