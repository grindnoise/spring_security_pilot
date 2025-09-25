package com.example.controller;

import com.example.entity.Cards;
import com.example.repository.CardsRepository;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class CardsController {

    private final CardsRepository cardsRepository;
    private final CustomerRepository customerRepository;

    // Keycloak
    @GetMapping("/myCards")
    public List<Cards> getCardDetails(@RequestParam String email) {
        return customerRepository
                .findByEmail(email)
                .map(customer -> cardsRepository.findByCustomerId(customer.getId()))
                .orElse(null);
    }

//    @GetMapping("/myCards")
//    public List<Cards> getCardDetails(@RequestParam long id) {
//        List<Cards> cards = cardsRepository.findByCustomerId(id);
//        if (cards != null ) {
//            return cards;
//        }else {
//            return null;
//        }
//    }

}
