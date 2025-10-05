package com.study.springsecurity.controller;

import com.study.springsecurity.dto.AuthenticationRequest;
import com.study.springsecurity.dto.AuthenticationResponse;
import com.study.springsecurity.dto.OAuth2Response;
import com.study.springsecurity.dto.RegisterRequest;
import com.study.springsecurity.enums.OAuth2Status;
import com.study.springsecurity.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authenticationService.register(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@Valid @RequestBody AuthenticationRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authenticationService.login(request, response));
    }

    @PostMapping("refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    @GetMapping("/success")
    public ResponseEntity<OAuth2Response> handleOAuth2Success() {
        return ResponseEntity.ok(OAuth2Response.builder()
                .status(OAuth2Status.SUCCESS)
                .message("Authentication successful")
                .timestamp(LocalDateTime.now())
                .build());
    }

    @GetMapping("/failure")
    public ResponseEntity<OAuth2Response> handleOAuth2Failure() {
        return ResponseEntity.ok(OAuth2Response.builder()
                .status(OAuth2Status.FAILURE)
                .message("Authentication failed")
                .timestamp(LocalDateTime.now())
                .build());
    }

}
