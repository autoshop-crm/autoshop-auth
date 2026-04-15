package com.vladko.autoshopauth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "app.security")
public class AppSecurityProperties {

    @NotNull
    private Jwt jwt = new Jwt();

    @Getter
    @Setter
    public static class Jwt {

        @NotBlank
        private String secret;

        @NotNull
        private Duration accessTtl;

        @NotNull
        private Duration refreshTtl;
    }
}
