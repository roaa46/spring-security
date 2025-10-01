package com.study.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api/v1/admin")
public class AdminController {
    @PreAuthorize("hasAuthority('admin:read')")
    @GetMapping
    public String get() {
        return "admin:get";
    }

    @PreAuthorize("hasAuthority('admin:create')")
    @PostMapping
    public String post() {
        return "admin:post";
    }

    @PreAuthorize("hasAuthority('admin:delete')")
    @DeleteMapping
    public String delete() {
        return "admin:delete";
    }

    @PreAuthorize("hasAuthority('admin:update')")
    @PutMapping
    public String put() {
        return "admin:put";
    }
}
