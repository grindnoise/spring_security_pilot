package com.example.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class RegisterRequestDto {
    private String email;
    @JsonProperty("pwd")
    private String password;
    private String role;
}
