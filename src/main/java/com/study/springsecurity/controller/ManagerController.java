package com.study.springsecurity.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/manager")
public class ManagerController {
    @GetMapping
    public String get() {
        return "manager:get";
    }

    @PostMapping
    public String post() {
        return "manager:post";
    }

    @DeleteMapping
    public String delete() {
        return "manager:delete";
    }

    @PutMapping
    public String put() {
        return "manager:put";
    }
}
