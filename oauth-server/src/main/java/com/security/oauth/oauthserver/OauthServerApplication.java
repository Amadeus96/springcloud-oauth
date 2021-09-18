package com.security.oauth.oauthserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableDiscoveryClient
@SpringBootApplication
public class OauthServerApplication {

    public static void main(String[] args) {

        SpringApplication.run(OauthServerApplication.class, args);
        System.out.println(new BCryptPasswordEncoder().encode("123456"));
    }

}
