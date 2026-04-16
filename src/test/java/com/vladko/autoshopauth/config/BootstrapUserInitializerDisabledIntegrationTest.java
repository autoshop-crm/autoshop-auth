package com.vladko.autoshopauth.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.vladko.autoshopauth.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(properties = "app.bootstrap.enabled=false")
@ActiveProfiles("test")
class BootstrapUserInitializerDisabledIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Value("${app.bootstrap.email}")
    private String bootstrapEmail;

    @Test
    void bootstrapUserIsNotCreatedWhenDisabled() {
        assertThat(userRepository.findByEmail(bootstrapEmail)).isEmpty();
    }
}
