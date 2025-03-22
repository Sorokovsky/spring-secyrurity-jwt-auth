package org.sorokovsky.jwtauth.service;

import lombok.RequiredArgsConstructor;
import org.sorokovsky.jwtauth.model.UserModel;
import org.sorokovsky.jwtauth.repository.UsersRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsersService implements UserDetailsService {
    private final UsersRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var exception = new UsernameNotFoundException(username);
        return UserModel.from(repository.findByEmail(username).orElseThrow(() -> exception));
    }
}
