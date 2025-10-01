package com.study.springsecurity;

import com.study.springsecurity.dto.RegisterRequest;
import com.study.springsecurity.service.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.study.springsecurity.enums.Role.ADMIN;
import static com.study.springsecurity.enums.Role.MANAGER;

@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);

    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {
        return args -> {

            var admin = RegisterRequest.builder()
                    .firstName("Super")
                    .lastName("Admin")
                    .email("superadmin@mail.com")
                    .password("password123")
                    .role(ADMIN)
                    .build();
            System.out.println("Admin token: " + authenticationService.register(admin).getAccessToken());

            var manager = RegisterRequest.builder()
                    .firstName("Super")
                    .lastName("Manager")
                    .email("supermanager@mail.com")
                    .password("password123")
                    .role(MANAGER)
                    .build();
            System.out.println("Manager token: " + authenticationService.register(manager).getAccessToken());

        };
    }

}
