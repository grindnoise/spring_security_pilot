package com.example.entity;

import com.example.dto.CustomerDto;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "customer")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String email;

    @Column(name = "pwd")
    private String password;

    @Column
    private String role;

    public CustomerDto toDto() {
        return CustomerDto.builder()
                .id(id)
                .email(email)
                .password(password)
                .role(role)
                .build();
    }
}
