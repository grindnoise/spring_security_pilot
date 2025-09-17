package com.example.controller;

import com.example.entity.Loans;
import com.example.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {

    private final LoanRepository loanRepository;

//        @PreAuthorize("hasRole('USER')")
//    @PostAuthorize("hasRole('ROOT')")
//    @PreAuthorize("hasRole('USER') and #id == authentication.principal.id")
    @PreAuthorize("@securityService.canAccessUserData(#id)")
    @GetMapping("/myLoans")
    public List<Loans> getLoanDetails(@RequestParam long id) {
        List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(id);
        if (loans != null) {
            return loans;
        } else {
            return null;
        }
    }

}
