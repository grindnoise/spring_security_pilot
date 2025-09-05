package com.example.service;

import com.example.dto.CustomerDto;
import com.example.manager.CustomerManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerManager customerManager;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public CustomerDto register(CustomerDto customerDto) {
        final var entity = customerDto.toNewEntity();
        entity.setPassword(passwordEncoder.encode(entity.getPassword()));
        return customerManager.save(entity).toDto();
    }
}
