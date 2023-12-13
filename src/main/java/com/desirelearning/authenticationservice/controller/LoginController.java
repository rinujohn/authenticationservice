package com.desirelearning.authenticationservice.controller;

import com.desirelearning.authenticationservice.entity.User;
import com.desirelearning.authenticationservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class LoginController {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepo;

    @RequestMapping ("/login")
    public User getUserDetailsAfterLogin(Authentication authentication) {
        List<User> customers = userRepo.findByEmail(authentication.getName());
        if (!customers.isEmpty()) {
            return customers.get(0);
        } else {
            return null;
        }

    }
    @GetMapping("/welcome")
    public String welcome(){
        return "Welcome";
    }
}
