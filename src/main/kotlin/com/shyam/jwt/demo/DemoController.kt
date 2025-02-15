package com.shyam.jwt.demo

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/demo-controller")
class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    fun sayHello() : ResponseEntity<String> {
        return ResponseEntity.ok("Hello from secured endpoint")
    }
}