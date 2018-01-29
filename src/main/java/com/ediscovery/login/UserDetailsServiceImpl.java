package com.ediscovery.login;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.util.Collections.emptyList;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    public UserDetailsServiceImpl(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("userdetail");
        AppUser appUser =userRepo.findByUsername(username);
        if (appUser == null) {
            throw new UsernameNotFoundException(username);
        }
        System.out.println("userdetail"+appUser.getUsername());
        return new User(appUser.getUsername(), appUser.getPassword(), emptyList());
    }
}
