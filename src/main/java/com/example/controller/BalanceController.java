package com.example.controller;

import com.example.entity.AccountTransactions;
import com.example.repository.AccountTransactionsRepository;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class BalanceController {

    private final AccountTransactionsRepository accountTransactionsRepository;
    private final CustomerRepository customerRepository;

    // Keycloak
    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam String email) {
        return customerRepository
                .findByEmail(email)
                .map(value -> accountTransactionsRepository.findByCustomerIdOrderByTransactionDtDesc(value.getId()))
                .orElse(null);
    }

//    @GetMapping("/myBalance")
//    public List<AccountTransactions> getBalanceDetails(@RequestParam long id) {
//        List<AccountTransactions> accountTransactions = accountTransactionsRepository.
//                findByCustomerIdOrderByTransactionDtDesc(id);
//        if (accountTransactions != null) {
//            return accountTransactions;
//        } else {
//            return null;
//        }
//    }
}
