package com.example.manager;

import com.example.entity.Customer;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class CustomerManager {

    private final CustomerRepository customerRepository;

    @Transactional
    public Customer save(Customer customer) {
        try {
            return customerRepository.save(customer);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
