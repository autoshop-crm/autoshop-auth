package com.vladko.autoshopauth.config;

import com.vladko.autoshopauth.role.entity.RoleName;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "app.bootstrap")
public class AppBootstrapProperties {

    private boolean enabled;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    @NotNull
    private RoleName role;
}
