package com.example.service;

// For Keycloak auth server we no longer need this
//@Service
//@RequiredArgsConstructor
//public class EazyBankUserDetailsService implements UserDetailsService {
//
//    private final CustomerRepository customerRepository;
//
//    @Override
//    public AuthorizedUser loadUserByUsername(String username) throws UsernameNotFoundException {
//        Customer customer = customerRepository.findByEmail(username).orElseThrow(() -> new
//                UsernameNotFoundException("User details not found for the user: " + username));
//        return new AuthorizedUser(customer);
////        return new User(customer.getEmail(),
////                customer.getPwd(),
////                customer.getAuthorities()
////                        .stream()
////                        .map(c -> new SimpleGrantedAuthority(c.getName()))
////                        .toList());
//    }
//}