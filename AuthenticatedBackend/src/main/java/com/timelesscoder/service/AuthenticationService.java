package com.timelesscoder.service;

import java.util.HashSet;
import java.util.Set;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.timelesscoder.model.ApplicationUser;
import com.timelesscoder.model.LoginResponseDto;
import com.timelesscoder.model.Role;
import com.timelesscoder.repository.RoleRepository;
import com.timelesscoder.repository.UserRepository;


@Service
@Transactional
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;


    public ApplicationUser register(String username,String password){

        String encodedPassword  = passwordEncoder.encode(password);
        System.out.println("sssssssssssssssssssssssssssss");
        Role usRole = roleRepository.findByAuthority("USER").get();

        Set<Role> roles = new HashSet<>();
        roles.add(usRole);
        return userRepository.save(new ApplicationUser(0, username, encodedPassword, roles));

    }

    public LoginResponseDto login(String username,String password){

        System.out.println("in loginnnnnnnnnnnnnnnnnnnnn");
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        //   Authentication auth = authenticationManager.authenticate(
        //     new UsernamePasswordAuthenticationToken(username, password)
        //     );
            System.out.println("insaaaaaaaaaaaa");
          String token = tokenService.generateJwt(auth);

      
          
          return new LoginResponseDto(userRepository.findByUsername(username).get(),token);

        } catch (AuthenticationException e) {
            return new LoginResponseDto(null,"");
        }


    }


}
