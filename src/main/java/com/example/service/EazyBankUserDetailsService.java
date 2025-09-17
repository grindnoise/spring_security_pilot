package com.example.service;


import com.example.dto.AuthorizedUser;
import com.example.entity.Customer;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EazyBankUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public AuthorizedUser loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = customerRepository.findByEmail(username).orElseThrow(() -> new
                UsernameNotFoundException("User details not found for the user: " + username));
        return new AuthorizedUser(customer);
//        return new User(customer.getEmail(),
//                customer.getPwd(),
//                customer.getAuthorities()
//                        .stream()
//                        .map(c -> new SimpleGrantedAuthority(c.getName()))
//                        .toList());
    }
}