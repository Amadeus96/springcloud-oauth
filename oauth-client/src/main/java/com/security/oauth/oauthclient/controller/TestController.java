package com.security.oauth.oauthclient.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
//    @GetMapping(value = "/get")
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
//    public Object get(Authentication authentication)
//    {
//        //Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        authentication.getCredentials();
//        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
//        String token = details.getTokenValue();
//        return token;
//    }

    @GetMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication;
    }


}
