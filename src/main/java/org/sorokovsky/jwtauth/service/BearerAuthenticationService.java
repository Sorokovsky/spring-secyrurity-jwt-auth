package org.sorokovsky.jwtauth.service;

import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.model.TokenModel;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@RequiredArgsConstructor
public class BearerAuthenticationService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    private final UserDetailsService userDetailsService;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken) throws UsernameNotFoundException {
        var token = (TokenModel) authenticationToken.getPrincipal();
        if (token == null) throw new UsernameNotFoundException("Token must be not null");
        return userDetailsService.loadUserByUsername(token.email());
    }
}
