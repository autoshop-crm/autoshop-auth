package com.vladko.autoshopauth.user.dto;

import com.vladko.autoshopauth.role.entity.RoleName;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record AdminUserCreateRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8, max = 72) String password,
        String firstName,
        String lastName,
        @NotEmpty Set<RoleName> roles
) {
}
