package org.sorokovsky.jwtauth.config;

import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.configurer.AuthenticationConfigurer;
import org.sorokovsky.jwtauth.repository.UsersRepository;
import org.sorokovsky.jwtauth.resolver.CurrentUserResolver;
import org.sorokovsky.jwtauth.serializer.TokenAuthenticationDetailsService;
import org.sorokovsky.jwtauth.strategy.BearerAccessTokenStorageStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig implements WebMvcConfigurer {
    private final UsersRepository usersRepository;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new CurrentUserResolver(usersRepository));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            BearerAccessTokenStorageStrategy bearerAccessTokenStorageStrategy,
            AuthenticationManager authenticationManager
    ) throws Exception {
        http.apply(new AuthenticationConfigurer())
                .bearerAccessTokenStorageStrategy(bearerAccessTokenStorageStrategy);
        return http
                .authenticationManager(authenticationManager)
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

    @Bean
    public AuthenticationManager authenticationManager(
            TokenAuthenticationDetailsService tokenAuthenticationDetailsService,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        var preAuth = new PreAuthenticatedAuthenticationProvider();
        preAuth.setPreAuthenticatedUserDetailsService(tokenAuthenticationDetailsService);
        var daoAuth = new DaoAuthenticationProvider();
        daoAuth.setPasswordEncoder(passwordEncoder);
        daoAuth.setUserDetailsService(userDetailsService);
        return new ProviderManager(Arrays.asList(preAuth, daoAuth));
    }
}
