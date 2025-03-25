package org.sorokovsky.jwtauth.provider;

import lombok.AllArgsConstructor;
import org.sorokovsky.jwtauth.service.BearerAuthenticationService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class BearerAuthenticationProvider implements AuthenticationProvider {
    private final BearerAuthenticationService bearerAuthenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var user = bearerAuthenticationService.loadUserDetails((PreAuthenticatedAuthenticationToken) authentication);
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(PreAuthenticatedAuthenticationToken.class);
    }
}
