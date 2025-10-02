package com.study.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api/v1/admin")
public class AdminController {
    @PreAuthorize("hasAuthority('admin:read')")
    @GetMapping
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("admin:get");
    }

    @PreAuthorize("hasAuthority('admin:create')")
    @PostMapping
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("admin:post");
    }

    @PreAuthorize("hasAuthority('admin:delete')")
    @DeleteMapping
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("admin:delete");
    }

    @PreAuthorize("hasAuthority('admin:update')")
    @PutMapping
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("admin:put");
    }
}
