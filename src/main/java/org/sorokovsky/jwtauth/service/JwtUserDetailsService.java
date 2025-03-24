package org.sorokovsky.jwtauth.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class JwtUserDetailsService implements AuthenticationUserDetailsService {
    @Override
    public UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
        return null;
    }
}
