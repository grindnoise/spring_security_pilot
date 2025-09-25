package com.example.controller;

import com.example.entity.Customer;
import com.example.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final CustomerRepository customerRepository;
    // For Keycloak auth server we no longer need it
    /*
    private final PasswordEncoder passwordEncoder;
    private final Environment environment;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            customer.setCreateDt(new Date(System.currentTimeMillis()));
            Customer savedCustomer = customerRepository.save(customer);

            if (savedCustomer.getId() > 0) {
                return ResponseEntity.status(HttpStatus.CREATED).
                        body("Given user details are successfully registered");
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).
                        body("User registration failed");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).
                    body("An exception occurred: " + ex.getMessage());
        }
    }

    @PostMapping("/apiLogin")
    public ResponseEntity<LoginResponseDto> apiLogin(@RequestBody LoginRequestDto loginRequest) {
        // Manually call bean authenticate()
        Authentication authentication = authenticationManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password()));
        if (authentication != null && authentication.isAuthenticated()) {
            final var secret = environment.getProperty(ApplicationConstants.JWT_SECRET_KEY, ApplicationConstants.JWT_SECRET_VALUE);
            final var secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            final var curDate = new java.util.Date();
            final AuthorizedUser authorizedUser = (AuthorizedUser) authentication.getPrincipal();
            final var jwt = Jwts.builder()
                    .issuer("superapp")
                    .claim("username", authorizedUser.getUsername())
                    .claim("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                    .issuedAt(curDate)
                    .expiration(new java.util.Date(curDate.getTime() + 3600000))
                    .signWith(secretKey)
                    .compact();
            return ResponseEntity.ok().header(ApplicationConstants.JWT_HEADER, jwt).body(new LoginResponseDto(HttpStatus.OK.toString(), jwt));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
    */

    @RequestMapping("/user")
    public Customer getUserDetailsAfterLogin(Authentication authentication) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
        return optionalCustomer.orElse(null);
    }

}
