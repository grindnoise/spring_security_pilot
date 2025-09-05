package com.example.dto;

import com.example.entity.Customer;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CustomerDto {
    private Long id;
    private String email;
    private String password;
    @Builder.Default
    private String role = "read";

    public static CustomerDto fromRequest(RegisterRequestDto request) {
        return CustomerDto.builder()
                .email(request.getEmail())
                .password(request.getPassword())
                .role(request.getRole())
                .build();
    }

    public Customer toNewEntity() {
        return Customer.builder()
                .email(email)
                .password(password)
                .role(role)
                .build();
    }
}
