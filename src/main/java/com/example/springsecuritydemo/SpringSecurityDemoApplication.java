package com.example.springsecuritydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.keygen.KeyGenerators;

@SpringBootApplication
public class SpringSecurityDemoApplication {


    public static void main(String[] args) {
        System.out.println(KeyGenerators.string().generateKey().toString());
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

}
