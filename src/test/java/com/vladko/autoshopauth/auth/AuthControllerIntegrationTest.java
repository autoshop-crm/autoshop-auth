package com.vladko.autoshopauth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vladko.autoshopauth.security.JwtService;
import com.vladko.autoshopauth.token.entity.CustomerActionTokenType;
import com.vladko.autoshopauth.token.entity.RefreshToken;
import com.vladko.autoshopauth.token.repository.CustomerActionTokenRepository;
import com.vladko.autoshopauth.token.repository.RefreshTokenRepository;
import com.vladko.autoshopauth.user.entity.User;
import com.vladko.autoshopauth.user.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.crypto.SecretKey;
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
    private CustomerActionTokenRepository customerActionTokenRepository;

    @Autowired
    private JwtService jwtService;

    @Value("${app.security.jwt.secret}")
    private String jwtSecret;

    @Value("${app.bootstrap.email}")
    private String bootstrapEmail;

    @Test
    void registerCreatesUserAndReturnsCustomerContract() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/api/auth/customers/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, "+79990001122", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.phoneNumber").value("+79990001122"))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.authUserId").isNumber())
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andExpect(jsonPath("$.accountStatus").value("ACTIVE"));

        User savedUser = userRepository.findByEmail(email).orElseThrow();
        assertThat(savedUser.getPasswordHash()).isNotEqualTo("StrongPass123");
        assertThat(savedUser.isActive()).isTrue();
        assertThat(savedUser.isEmailVerified()).isFalse();
        assertThat(savedUser.getRoles()).extracting(role -> role.getName().name()).contains("CUSTOMER");
    }

    @Test
    void registerIgnoresInvalidBearerTokenOnPublicEndpoint() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/api/auth/customers/register")
                        .header(HttpHeaders.AUTHORIZATION, bearer("definitely-not-a-jwt"))
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, "+79990001123", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")));
    }

    @Test
    void legacyRegisterPathStaysCompatible() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, "+79990002233", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    void bootstrapUserIsCreatedForTestProfile() {
        User bootstrapUser = userRepository.findByEmail(bootstrapEmail).orElseThrow();
        assertThat(bootstrapUser.isActive()).isTrue();
        assertThat(bootstrapUser.getRoles()).extracting(role -> role.getName().name()).contains("MANAGER");
    }

    @Test
    void devUsersAreCreatedForRoleSmokeTests() {
        assertDevUser("admin@autoshop.local", "ADMIN");
        assertDevUser("manager@autoshop.local", "MANAGER");
        assertDevUser("reception@autoshop.local", "RECEPTIONIST");
        assertDevUser("mechanic@autoshop.local", "MECHANIC");
        assertDevUser("customer@autoshop.local", "CUSTOMER");
    }

    @Test
    void registerDuplicateEmailReturns409() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        mockMvc.perform(post("/api/auth/customers/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, "+79990003344", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("User with this email already exists"));
    }

    @Test
    void loginReturnsAccessAndRefreshTokensAndCustomerRole() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        MvcResult result = mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, "StrongPass123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.accountStatus").value("ACTIVE"))
                .andReturn();

        JsonNode loginJson = readJson(result);
        var claims = jwtService.parseAccessToken(loginJson.get("accessToken").asText());
        assertThat(claims.email()).isEqualTo(email);
        assertThat(claims.roles()).contains("CUSTOMER");
    }

    @Test
    void registerWithUppercaseEmailCanLoginWithLowercase() throws Exception {
        String originalEmail = "User-" + UUID.randomUUID() + "@Example.com";
        String normalizedEmail = originalEmail.toLowerCase();

        mockMvc.perform(post("/api/auth/customers/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(originalEmail, "+79990004455", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(normalizedEmail));

        mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(normalizedEmail, "StrongPass123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(normalizedEmail))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")));
    }

    @Test
    void loginWithInvalidPasswordReturns401() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, "WrongPass123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void refreshRotatesTokensAndKeepsCustomerRole() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");

        JsonNode loginJson = loginUser(email, "StrongPass123");
        String oldAccessToken = loginJson.get("accessToken").asText();
        String oldRefreshTokenValue = loginJson.get("refreshToken").asText();

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/customers/refresh")
                        .contentType(APPLICATION_JSON)
                        .content(refreshPayload(oldRefreshTokenValue)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        JsonNode refreshJson = readJson(refreshResult);
        String newAccessToken = refreshJson.get("accessToken").asText();
        String newRefreshTokenValue = refreshJson.get("refreshToken").asText();

        assertThat(newRefreshTokenValue).isNotEqualTo(oldRefreshTokenValue);
        assertThat(jwtService.parseAccessToken(newAccessToken).jti())
                .isNotEqualTo(jwtService.parseAccessToken(oldAccessToken).jti());
        assertThat(jwtService.parseAccessToken(newAccessToken).roles()).contains("CUSTOMER");

        RefreshToken oldRefreshToken = refreshTokenRepository.findByToken(oldRefreshTokenValue).orElseThrow();
        RefreshToken newRefreshToken = refreshTokenRepository.findByToken(newRefreshTokenValue).orElseThrow();
        assertThat(oldRefreshToken.isRevoked()).isTrue();
        assertThat(newRefreshToken.isRevoked()).isFalse();
    }

    @Test
    void validateReturnsClaimsForCustomerToken() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");

        mockMvc.perform(post("/api/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, bearer(loginJson.get("accessToken").asText())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.tokenType").value("access"))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.jti").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());
    }

    @Test
    void meReturnsCurrentUserForValidCustomerToken() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");

        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(loginJson.get("accessToken").asText())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(loginJson.get("userId").asLong()))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")))
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());
    }

    @Test
    void customerLogoutRevokesSession() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");

        String accessToken = loginJson.get("accessToken").asText();
        String refreshToken = loginJson.get("refreshToken").asText();

        mockMvc.perform(post("/api/auth/customers/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken))
                        .contentType(APPLICATION_JSON)
                        .content(logoutPayload(refreshToken)))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Access token is revoked"));
    }

    @Test
    void forgotPasswordDoesNotLeakUserExistenceAndCreatesResetTokenForExistingUser() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        Long userId = userRepository.findByEmail(email).orElseThrow().getId();

        mockMvc.perform(post("/api/auth/customers/password/forgot")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s"
                                }
                                """.formatted(email)))
                .andExpect(status().isAccepted());

        assertThat(customerActionTokenRepository
                .findTopByUserIdAndTypeOrderByCreatedAtDesc(userId, CustomerActionTokenType.PASSWORD_RESET))
                .isPresent();

        mockMvc.perform(post("/api/auth/customers/password/forgot")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s"
                                }
                                """.formatted(uniqueEmail())))
                .andExpect(status().isAccepted());
    }

    @Test
    void resetPasswordUpdatesCredentialsAndRevokesRefreshTokens() throws Exception {
        String email = uniqueEmail();
        registerUser(email, "StrongPass123");
        JsonNode loginJson = loginUser(email, "StrongPass123");
        Long userId = userRepository.findByEmail(email).orElseThrow().getId();

        mockMvc.perform(post("/api/auth/customers/password/forgot")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s"
                                }
                                """.formatted(email)))
                .andExpect(status().isAccepted());

        String resetToken = customerActionTokenRepository
                .findTopByUserIdAndTypeOrderByCreatedAtDesc(userId, CustomerActionTokenType.PASSWORD_RESET)
                .orElseThrow()
                .getToken();

        mockMvc.perform(post("/api/auth/customers/password/reset")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "%s",
                                  "newPassword": "NewStrongPass123"
                                }
                                """.formatted(resetToken)))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, "StrongPass123")))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, "NewStrongPass123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", hasItem("CUSTOMER")));

        mockMvc.perform(post("/api/auth/customers/refresh")
                        .contentType(APPLICATION_JSON)
                        .content(refreshPayload(loginJson.get("refreshToken").asText())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token is invalid"));
    }

    @Test
    void verifyEmailMarksUserVerified() throws Exception {
        String email = uniqueEmail();
        MvcResult registerResult = mockMvc.perform(post("/api/auth/customers/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, "+79990005566", "StrongPass123", "Ivan", "Petrov")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andReturn();

        Long userId = readJson(registerResult).get("authUserId").asLong();
        String verificationToken = customerActionTokenRepository
                .findTopByUserIdAndTypeOrderByCreatedAtDesc(userId, CustomerActionTokenType.EMAIL_VERIFICATION)
                .orElseThrow()
                .getToken();

        mockMvc.perform(post("/api/auth/customers/email/verify")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "%s"
                                }
                                """.formatted(verificationToken)))
                .andExpect(status().isNoContent());

        User user = userRepository.findByEmail(email).orElseThrow();
        assertThat(user.isEmailVerified()).isTrue();

        mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, "StrongPass123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.emailVerified").value(true));
    }

    @Test
    void adminCannotCreateCustomerThroughStaffEndpoint() throws Exception {
        JsonNode adminLogin = loginUser("admin@autoshop.local", "Admin123!");

        mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminLogin.get("accessToken").asText()))
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "CustomerPass123!",
                                  "roles": ["CUSTOMER"]
                                }
                                """.formatted(uniqueEmail())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("CUSTOMER users must be created through public registration"));
    }

    @Test
    void adminCanCreateStaffUser() throws Exception {
        JsonNode adminLogin = loginUser("admin@autoshop.local", "Admin123!");
        String managerEmail = uniqueEmail();

        mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminLogin.get("accessToken").asText()))
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "ManagerPass123!",
                                  "firstName": "New",
                                  "lastName": "Manager",
                                  "roles": ["MANAGER"]
                                }
                                """.formatted(managerEmail)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(managerEmail))
                .andExpect(jsonPath("$.roles", hasItem("MANAGER")));
    }

    @Test
    void adminCanCreateStaffUserWhenJwtContainsPrefixedRole() throws Exception {
        User adminUser = userRepository.findByEmail("admin@autoshop.local").orElseThrow();
        String managerEmail = uniqueEmail();

        mockMvc.perform(post("/api/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken(adminUser, List.of("ROLE_ADMIN"))))
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "ManagerPass123!",
                                  "firstName": "New",
                                  "lastName": "Manager",
                                  "roles": ["MANAGER"]
                                }
                                """.formatted(managerEmail)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(managerEmail))
                .andExpect(jsonPath("$.roles", hasItem("MANAGER")));
    }

    private void registerUser(String email, String password) throws Exception {
        mockMvc.perform(post("/api/auth/customers/register")
                        .contentType(APPLICATION_JSON)
                        .content(registerPayload(email, null, password, null, null)))
                .andExpect(status().isCreated());
    }

    private JsonNode loginUser(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/customers/login")
                        .contentType(APPLICATION_JSON)
                        .content(loginPayload(email, password)))
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

    private String accessToken(User user, List<String> roles) {
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(String.valueOf(user.getId()))
                .claim("email", user.getEmail())
                .claim("roles", roles)
                .claim("type", "access")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .signWith(secretKey)
                .compact();
    }

    private String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private void assertDevUser(String email, String roleName) {
        User user = userRepository.findByEmail(email).orElseThrow();
        assertThat(user.isActive()).isTrue();
        assertThat(user.getRoles()).extracting(role -> role.getName().name()).contains(roleName);
    }

    private String registerPayload(String email, String phoneNumber, String password, String firstName, String lastName) {
        String phonePart = phoneNumber == null ? "null" : "\"%s\"".formatted(phoneNumber);
        String firstNamePart = firstName == null ? "null" : "\"%s\"".formatted(firstName);
        String lastNamePart = lastName == null ? "null" : "\"%s\"".formatted(lastName);
        return """
                {
                  "email": "%s",
                  "phoneNumber": %s,
                  "password": "%s",
                  "firstName": %s,
                  "lastName": %s,
                  "acceptTerms": true,
                  "acceptPrivacyPolicy": true
                }
                """.formatted(email, phonePart, password, firstNamePart, lastNamePart);
    }

    private String loginPayload(String email, String password) {
        return """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(email, password);
    }

    private String refreshPayload(String refreshToken) {
        return """
                {
                  "refreshToken": "%s"
                }
                """.formatted(refreshToken);
    }

    private String logoutPayload(String refreshToken) {
        return refreshPayload(refreshToken);
    }
}
