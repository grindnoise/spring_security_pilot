package com.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j
@SpringBootApplication
//@EnableWebSecurity(debug = true)
// Use if entities/repositories are outside the src root
//@EntityScan("com.example.entity")
//@EnableJpaRepositories("com.example.repository")
public class EazyBankBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(EazyBankBackendApplication.class, args);
	}

//	@Bean
//	@Transactional
//	public CommandLineRunner commandLineRunner(CustomerRepository customerRepository) {
//		return args -> {
//			final var customer = customerRepository.findById(1L).get();
//			log.info(customer.getAuthorities().toString());
//		};
//	}
}
