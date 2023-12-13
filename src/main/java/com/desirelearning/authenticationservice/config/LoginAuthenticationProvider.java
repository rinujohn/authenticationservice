package com.desirelearning.authenticationservice.config;

import com.desirelearning.authenticationservice.entity.User;
import com.desirelearning.authenticationservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<User> customer = userRepo.findByEmail(username);

        if (customer.size() > 0) {
            if (passwordEncoder.matches(pwd, customer.get(0).getPassword())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customer.get(0).getRoles()));
                return new UsernamePasswordAuthenticationToken(username, pwd,authorities);
            } else {
                throw new BadCredentialsException("Invalid password!");
            }
        }else {
            throw new BadCredentialsException("No user registered with this details!");
        }

    }

//    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
//        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
//        for (Authority authority : authorities) {
//            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
//        }
//        return grantedAuthorities;
//    }
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
