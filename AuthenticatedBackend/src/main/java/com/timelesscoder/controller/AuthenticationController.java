package com.timelesscoder.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.timelesscoder.model.ApplicationUser;
import com.timelesscoder.model.LoginResponseDto;
import com.timelesscoder.model.RegistrationDto;
import com.timelesscoder.service.AuthenticationService;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public ApplicationUser register(@RequestBody RegistrationDto body){
        return authenticationService.register(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDto loginUser(@RequestBody RegistrationDto body){
        return authenticationService.login(body.getUsername(), body.getPassword());
    }
}
