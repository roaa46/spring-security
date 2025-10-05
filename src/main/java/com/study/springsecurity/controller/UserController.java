package com.study.springsecurity.controller;

import com.study.springsecurity.dto.changePasswordRequest;
import com.study.springsecurity.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PatchMapping
    public ResponseEntity<?> changePassword(@Valid @RequestBody changePasswordRequest request, Principal connectedUser) {
        userService.changePassword(request, connectedUser);
        return ResponseEntity.accepted().build();
    }

    @GetMapping
    public ResponseEntity<String > get() {
        return ResponseEntity.ok("Hello User!");
    }
}
