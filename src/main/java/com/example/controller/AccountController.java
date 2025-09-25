package com.example.controller;

import com.example.entity.Account;
import com.example.repository.AccountsRepository;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final AccountsRepository accountsRepository;
    private final CustomerRepository customerRepository;

    // Keycloak
    @GetMapping("/myAccount")
    public Account getAccountDetails(@RequestParam String email) {
        return customerRepository
                .findByEmail(email)
                .map(customer -> accountsRepository.findByCustomerId(customer.getId()))
                .orElse(null);
    }

//    @GetMapping("/myAccount")
//    public Accounts getAccountDetails(@RequestParam long id) {
//        Accounts accounts = accountsRepository.findByCustomerId(id);
//        if (accounts != null) {
//            return accounts;
//        } else {
//            return null;
//        }
//    }
}
