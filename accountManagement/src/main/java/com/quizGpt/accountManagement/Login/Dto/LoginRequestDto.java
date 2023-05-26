package com.quizGpt.accountManagement.Login.Dto;

import java.io.Serializable;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class LoginRequestDto implements Serializable{
    @NotBlank
    private String Username;

    @NotBlank
    private String Password;
}
