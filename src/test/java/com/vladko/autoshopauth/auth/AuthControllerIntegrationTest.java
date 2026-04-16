package com.vladko.autoshopauth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vladko.autoshopauth.security.JwtService;
import com.vladko.autoshopauth.token.entity.RefreshToken;
import com.vladko.autoshopauth.token.repository.RefreshTokenRepository;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private JwtService jwtService;

    @Value("${app.bootstrap.email}")
    private String bootstrapEmail;

    @Test
    void registerCreatesUserAndReturns201() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "StrongPass123",
                                  "firstName": "Ivan",
                                  "lastName": "Petrov"
                                }
                                """.formatted(email)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles", hasItem("CLIENT")));

        User savedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(savedUser.getPasswordHash()).isNotEqualTo("StrongPass123");
        assertThat(savedUser.isActive()).isTrue();
    }

    @Test
    void bootstrapUserIsCreatedForTestProfile() {
        User bootstrapUser = userRepository.findByEmail(bootstrapEmail).orElseThrow();
        assertThat(bootstrapUser.isActive()).isTrue();
        assertThat(bootstrapUser.getRoles()).extracting(role -> role.getName().name()).contains("MANAGER");
    }

    @Test
    void registerDuplicateEmailReturns409() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "StrongPass123"
                                }
                                """.formatted(email)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("User with this email already exists"));
    }

    @Test
    void loginReturnsAccessAndRefreshTokensAndAccessTokenContainsJti() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "StrongPass123"
                                }
                                """.formatted(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles", hasItem("CLIENT")))
                .andReturn();

        JsonNode json = readJson(result);
        var claims = jwtService.parseAccessToken(json.get("accessToken").asText());

        assertThat(claims.jti()).isNotBlank();
        assertThat(claims.type()).isEqualTo("access");
        assertThat(claims.email()).isEqualTo(email);
    }

    @Test
    void loginWithWrongPasswordReturns401() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "WrongPassword"
                                }
                                """.formatted(email)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void refreshReturnsNewTokenPairAndRevokesOldRefreshTokenAndRotatesJti() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        JsonNode loginJson = loginUser(email, "StrongPass123");
        String oldAccessToken = loginJson.get("accessToken").asText();
        String oldRefreshTokenValue = loginJson.get("refreshToken").asText();

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(oldRefreshTokenValue)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        JsonNode refreshJson = readJson(refreshResult);
        String newAccessToken = refreshJson.get("accessToken").asText();
        String newRefreshTokenValue = refreshJson.get("refreshToken").asText();

        assertThat(newRefreshTokenValue).isNotEqualTo(oldRefreshTokenValue);
        assertThat(jwtService.parseAccessToken(newAccessToken).jti())
                .isNotEqualTo(jwtService.parseAccessToken(oldAccessToken).jti());

        RefreshToken oldRefreshToken = refreshTokenRepository.findByToken(oldRefreshTokenValue).orElseThrow();
        RefreshToken newRefreshToken = refreshTokenRepository.findByToken(newRefreshTokenValue).orElseThrow();

        assertThat(oldRefreshToken.isRevoked()).isTrue();
        assertThat(newRefreshToken.isRevoked()).isFalse();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(oldRefreshTokenValue)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token is invalid"));
    }

    @Test
    void refreshWithUnknownTokenReturns401() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "unknown-token"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token is invalid"));
    }

    @Test
    void validateReturnsClaimsForValidAccessToken() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");
        String accessToken = loginJson.get("accessToken").asText();

        mockMvc.perform(post("/api/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.tokenType").value("access"))
                .andExpect(jsonPath("$.roles", hasItem("CLIENT")))
                .andExpect(jsonPath("$.jti").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());
    }

    @Test
    void logoutBlacklistsAccessTokenAndRevokesRefreshToken() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");

        String accessToken = loginJson.get("accessToken").asText();
        String refreshToken = loginJson.get("refreshToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken))
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(refreshToken)))
                .andExpect(status().isOk());

        RefreshToken persistedRefreshToken = refreshTokenRepository.findByToken(refreshToken).orElseThrow();
        assertThat(persistedRefreshToken.isRevoked()).isTrue();

        mockMvc.perform(post("/api/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Access token is revoked"));
    }

    @Test
    void logoutWithInvalidBearerReturns401() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "some-token"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Access token is invalid"));
    }

    @Test
    void logoutWithForeignRefreshTokenReturns401AndDoesNotRevokeForeignSession() throws Exception {
        String firstEmail = uniqueEmail();
        String secondEmail = uniqueEmail();
        registerUser(firstEmail, "StrongPass123");
        registerUser(secondEmail, "StrongPass123");

        JsonNode firstLogin = loginUser(firstEmail, "StrongPass123");
        JsonNode secondLogin = loginUser(secondEmail, "StrongPass123");

        String firstAccessToken = firstLogin.get("accessToken").asText();
        String secondRefreshToken = secondLogin.get("refreshToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(firstAccessToken))
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(secondRefreshToken)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token does not belong to the current user"));

        RefreshToken foreignRefreshToken = refreshTokenRepository.findByToken(secondRefreshToken).orElseThrow();
        assertThat(foreignRefreshToken.isRevoked()).isFalse();
    }

    @Test
    void inactiveUserCannotValidateOrRefresh() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");

        User user = userRepository.findByEmail(email).orElseThrow();
        user.setActive(false);
        userRepository.save(user);

        mockMvc.perform(post("/api/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, bearer(loginJson.get("accessToken").asText())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Access token is invalid"));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "refreshToken": "%s"
                                }
                                """.formatted(loginJson.get("refreshToken").asText())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token is invalid"));
    }

    private void registerUser(String email, String password) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isCreated());
    }

    private JsonNode loginUser(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andReturn();

        return readJson(result);
    }

    private JsonNode readJson(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    private String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }
}
