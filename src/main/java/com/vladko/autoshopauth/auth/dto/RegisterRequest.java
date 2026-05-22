package com.vladko.autoshopauth.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Email String email,
        @Pattern(regexp = "^$|^\\+?[0-9]{10,20}$", message = "must be a valid phone number") String phoneNumber,
        @NotBlank @Size(min = 8, max = 72) String password,
        String firstName,
        String lastName,
        @AssertTrue(message = "must be accepted") boolean acceptTerms,
        @AssertTrue(message = "must be accepted") boolean acceptPrivacyPolicy
) {
}
