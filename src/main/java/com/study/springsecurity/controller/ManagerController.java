package com.study.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/manager")
public class ManagerController {
    @GetMapping
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("manager:get");
    }

    @PostMapping
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("manager:post");
    }

    @DeleteMapping
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("manager:delete");
    }

    @PutMapping
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("manager:put");
    }
}
