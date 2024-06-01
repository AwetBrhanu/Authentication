package com.timelesscoder.model;


public class LoginResponseDto {

    private ApplicationUser user;
    private String jwt;
    
    public LoginResponseDto() {
    }

    
    public LoginResponseDto(ApplicationUser user, String jwt) {
        this.user = user;
        this.jwt = jwt;
    }


    public ApplicationUser getUser() {
        return user;
    }


    public void setUser(ApplicationUser user) {
        this.user = user;
    }


    public String getJwt() {
        return jwt;
    }


    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    
}
