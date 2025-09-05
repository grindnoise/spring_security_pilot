package com.example.controller;

import com.example.dto.CustomerDto;
import com.example.dto.RegisterRequestDto;
import com.example.service.CustomerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final CustomerService customerService;

    @PostMapping("/register")
    public ResponseEntity<CustomerDto> register(@RequestBody @Validated RegisterRequestDto request) {
        try {
            return ResponseEntity.ok(customerService.register(CustomerDto.fromRequest(request)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

}
