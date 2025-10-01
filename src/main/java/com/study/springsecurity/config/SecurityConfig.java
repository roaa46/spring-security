package com.study.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.study.springsecurity.enums.Permission.*;
import static com.study.springsecurity.enums.Role.ADMIN;
import static com.study.springsecurity.enums.Role.MANAGER;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final DaoAuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth

                                .requestMatchers("/api/v1/auth/**").permitAll()

//                        .requestMatchers("/api/v1/manager/**").hasAnyRole(ADMIN, MANAGER)
//                        .requestMatchers("/api/v1/admin/**").hasRole(ADMIN)

                                .requestMatchers("/api/v1/manager/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(HttpMethod.GET, "/api/v1/manager/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                .requestMatchers(HttpMethod.POST, "/api/v1/manager/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                .requestMatchers(HttpMethod.DELETE, "/api/v1/manager/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
                                .requestMatchers(HttpMethod.PUT, "/api/v1/manager/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())

//                        .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())
//                                .requestMatchers(HttpMethod.GET,"/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
//                                .requestMatchers(HttpMethod.POST,"/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
//                                .requestMatchers(HttpMethod.DELETE,"/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())
//                                .requestMatchers(HttpMethod.PUT,"/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())

                                .anyRequest().authenticated()
                )
                .userDetailsService(userDetailsService)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider)
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(((request, response, authentication) ->
                                        SecurityContextHolder.clearContext()
                                )
                        ));

        return http.build();
    }
}
