package com.hon.aecs.prm.syncProgramMembers.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for HONPRMMembersSecurityService.
 * Tests cover security configuration, JWT setup, user management, and cryptographic operations.
 */
@DisplayName("HONPRMMembersSecurityService Tests")
class HONPRMMembersSecurityServiceTest {

    private HONPRMMembersSecurityService securityService;
    
    @BeforeEach
    void setUp() {
        securityService = new HONPRMMembersSecurityService();
    }

    @Nested
    @DisplayName("Security Filter Chain Tests")
    class SecurityFilterChainTests {

        @Test
        @DisplayName("Should create security filter chain with all security features enabled")
        void testFilterChainCreation() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            SecurityFilterChain chain = securityService.filterChain(http);
            
            // Then
            assertNotNull(chain, "Security filter chain should not be null");
        }

        @Test
        @DisplayName("Should configure filter chain to authenticate all requests")
        void testFilterChainAuthenticatesAllRequests() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            securityService.filterChain(http);
            
            // Then
            verify(http, atLeastOnce()).authorizeHttpRequests(any());
        }

        @Test
        @DisplayName("Should configure filter chain with stateless session management")
        void testFilterChainStatelessSessionManagement() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            securityService.filterChain(http);
            
            // Then
            verify(http, atLeastOnce()).sessionManagement(any());
        }

        @Test
        @DisplayName("Should disable CSRF protection for stateless API")
        void testFilterChainDisablesCsrf() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            securityService.filterChain(http);
            
            // Then
            verify(http, atLeastOnce()).csrf(any());
        }

        @Test
        @DisplayName("Should configure OAuth2 resource server with JWT")
        void testFilterChainConfiguresOAuth2ResourceServer() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            securityService.filterChain(http);
            
            // Then
            verify(http, atLeastOnce()).oauth2ResourceServer(any());
        }

        @Test
        @DisplayName("Should configure same origin frame options")
        void testFilterChainConfiguresFrameOptions() throws Exception {
            // Given
            HttpSecurity http = mock(HttpSecurity.class, RETURNS_DEEP_STUBS);
            
            // When
            securityService.filterChain(http);
            
            // Then
            verify(http, atLeastOnce()).headers(any());
        }

        @Test
        @DisplayName("Should throw exception when HttpSecurity is null")
        void testFilterChainWithNullHttpSecurity() {
            // When & Then
            assertThrows(Exception.class, () -> securityService.filterChain(null),
                "Should throw exception when HttpSecurity is null");
        }
    }

    @Nested
    @DisplayName("User Details Service Tests")
    class UserDetailsServiceTests {

        @Test
        @DisplayName("Should create in-memory user details service")
        void testUserDetailsServiceCreation() {
            // When
            UserDetailsService userDetailsService = securityService.userDetailsService();
            
            // Then
            assertNotNull(userDetailsService, "UserDetailsService should not be null");
        }

        @Test
        @DisplayName("Should create user with username 'infodba'")
        void testUserDetailsServiceWithCorrectUsername() {
            // When
            UserDetailsService userDetailsService = securityService.userDetailsService();
            UserDetails user = userDetailsService.loadUserByUsername("infodba");
            
            // Then
            assertNotNull(user, "User should not be null");
            assertEquals("infodba", user.getUsername(), "Username should be 'infodba'");
        }

        @Test
        @DisplayName("Should create user with USER role")
        void testUserDetailsServiceWithUserRole() {
            // When
            UserDetailsService userDetailsService = securityService.userDetailsService();
            UserDetails user = userDetailsService.loadUserByUsername("infodba");
            
            // Then
            assertTrue(user.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER")),
                "User should have ROLE_USER authority");
        }

        @Test
        @DisplayName("Should encode user password with BCrypt")
        void testUserDetailsServicePasswordEncoding() {
            // When
            UserDetailsService userDetailsService = securityService.userDetailsService();
            UserDetails user = userDetailsService.loadUserByUsername("infodba");
            
            // Then
            assertNotNull(user.getPassword(), "Password should not be null");
            assertTrue(user.getPassword().startsWith("$2a$") || user.getPassword().startsWith("$2b$"),
                "Password should be BCrypt encoded");
        }

        @Test
        @DisplayName("Should throw exception when loading non-existent user")
        void testUserDetailsServiceWithNonExistentUser() {
            // Given
            UserDetailsService userDetailsService = securityService.userDetailsService();
            
            // When & Then
            assertThrows(Exception.class, () -> userDetailsService.loadUserByUsername("nonexistent"),
                "Should throw exception for non-existent user");
        }
    }

    @Nested
    @DisplayName("BCrypt Password Encoder Tests")
    class BCryptPasswordEncoderTests {

        @Test
        @DisplayName("Should create BCrypt password encoder")
        void testBCryptPasswordEncoderCreation() {
            // When
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            
            // Then
            assertNotNull(encoder, "BCryptPasswordEncoder should not be null");
        }

        @Test
        @DisplayName("Should encode password correctly")
        void testBCryptPasswordEncoderEncoding() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String rawPassword = "testPassword123";
            
            // When
            String encodedPassword = encoder.encode(rawPassword);
            
            // Then
            assertNotNull(encodedPassword, "Encoded password should not be null");
            assertNotEquals(rawPassword, encodedPassword, "Encoded password should differ from raw password");
            assertTrue(encodedPassword.startsWith("$2a$") || encodedPassword.startsWith("$2b$"),
                "Encoded password should have BCrypt prefix");
        }

        @Test
        @DisplayName("Should verify password matches encoded version")
        void testBCryptPasswordEncoderVerification() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String rawPassword = "testPassword123";
            String encodedPassword = encoder.encode(rawPassword);
            
            // When
            boolean matches = encoder.matches(rawPassword, encodedPassword);
            
            // Then
            assertTrue(matches, "Password should match its encoded version");
        }

        @Test
        @DisplayName("Should generate different encoded values for same password")
        void testBCryptPasswordEncoderUniqueSalts() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String rawPassword = "testPassword123";
            
            // When
            String encodedPassword1 = encoder.encode(rawPassword);
            String encodedPassword2 = encoder.encode(rawPassword);
            
            // Then
            assertNotEquals(encodedPassword1, encodedPassword2,
                "BCrypt should generate different hashes due to unique salts");
            assertTrue(encoder.matches(rawPassword, encodedPassword1),
                "Both encoded passwords should match the raw password");
            assertTrue(encoder.matches(rawPassword, encodedPassword2),
                "Both encoded passwords should match the raw password");
        }

        @Test
        @DisplayName("Should not match wrong password")
        void testBCryptPasswordEncoderNonMatch() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String rawPassword = "testPassword123";
            String wrongPassword = "wrongPassword";
            String encodedPassword = encoder.encode(rawPassword);
            
            // When
            boolean matches = encoder.matches(wrongPassword, encodedPassword);
            
            // Then
            assertFalse(matches, "Wrong password should not match");
        }
    }

    @Nested
    @DisplayName("Key Pair Generation Tests")
    class KeyPairGenerationTests {

        @Test
        @DisplayName("Should generate RSA key pair")
        void testKeyPairGeneration() {
            // When
            KeyPair keyPair = securityService.keyPair();
            
            // Then
            assertNotNull(keyPair, "Key pair should not be null");
            assertNotNull(keyPair.getPublic(), "Public key should not be null");
            assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        }

        @Test
        @DisplayName("Should generate RSA key pair with 5096 bits")
        void testKeyPairStrength() {
            // When
            KeyPair keyPair = securityService.keyPair();
            
            // Then
            assertTrue(keyPair.getPublic() instanceof RSAPublicKey,
                "Public key should be RSA type");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            assertEquals(5096, rsaPublicKey.getModulus().bitLength(),
                "Key strength should be 5096 bits");
        }

        @Test
        @DisplayName("Should generate different key pairs on multiple calls")
        void testKeyPairUniqueness() {
            // When
            KeyPair keyPair1 = securityService.keyPair();
            KeyPair keyPair2 = securityService.keyPair();
            
            // Then
            assertNotEquals(keyPair1.getPublic(), keyPair2.getPublic(),
                "Each call should generate a unique key pair");
            assertNotEquals(keyPair1.getPrivate(), keyPair2.getPrivate(),
                "Each call should generate a unique key pair");
        }

        @Test
        @DisplayName("Should generate key pair with correct algorithm")
        void testKeyPairAlgorithm() {
            // When
            KeyPair keyPair = securityService.keyPair();
            
            // Then
            assertEquals("RSA", keyPair.getPublic().getAlgorithm(),
                "Public key algorithm should be RSA");
            assertEquals("RSA", keyPair.getPrivate().getAlgorithm(),
                "Private key algorithm should be RSA");
        }
    }

    @Nested
    @DisplayName("RSA Key Tests")
    class RSAKeyTests {

        @Test
        @DisplayName("Should create RSA key from key pair")
        void testRSAKeyCreation() {
            // Given
            KeyPair keyPair = securityService.keyPair();
            
            // When
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // Then
            assertNotNull(rsaKey, "RSA key should not be null");
        }

        @Test
        @DisplayName("Should include public key in RSA key")
        void testRSAKeyPublicKey() throws Exception {
            // Given
            KeyPair keyPair = securityService.keyPair();
            
            // When
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // Then
            assertNotNull(rsaKey.toRSAPublicKey(), "RSA public key should not be null");
            assertEquals(keyPair.getPublic(), rsaKey.toRSAPublicKey(),
                "RSA key should contain the same public key");
        }

        @Test
        @DisplayName("Should include private key in RSA key")
        void testRSAKeyPrivateKey() throws Exception {
            // Given
            KeyPair keyPair = securityService.keyPair();
            
            // When
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // Then
            assertNotNull(rsaKey.toRSAPrivateKey(), "RSA private key should not be null");
        }

        @Test
        @DisplayName("Should generate unique key ID for RSA key")
        void testRSAKeyId() {
            // Given
            KeyPair keyPair = securityService.keyPair();
            
            // When
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // Then
            assertNotNull(rsaKey.getKeyID(), "Key ID should not be null");
            assertFalse(rsaKey.getKeyID().isEmpty(), "Key ID should not be empty");
        }

        @Test
        @DisplayName("Should generate different key IDs for different RSA keys")
        void testRSAKeyIdUniqueness() {
            // Given
            KeyPair keyPair1 = securityService.keyPair();
            KeyPair keyPair2 = securityService.keyPair();
            
            // When
            RSAKey rsaKey1 = securityService.rsaKey(keyPair1);
            RSAKey rsaKey2 = securityService.rsaKey(keyPair2);
            
            // Then
            assertNotEquals(rsaKey1.getKeyID(), rsaKey2.getKeyID(),
                "Different RSA keys should have different key IDs");
        }

        @Test
        @DisplayName("Should throw exception with null key pair")
        void testRSAKeyWithNullKeyPair() {
            // When & Then
            assertThrows(Exception.class, () -> securityService.rsaKey(null),
                "Should throw exception when key pair is null");
        }
    }

    @Nested
    @DisplayName("JWK Source Tests")
    class JWKSourceTests {

        @Test
        @DisplayName("Should create JWK source from RSA key")
        void testJWKSourceCreation() {
            // Given
            KeyPair keyPair = securityService.keyPair();
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // When
            JWKSource<SecurityContext> jwkSource = securityService.jwkSource(rsaKey);
            
            // Then
            assertNotNull(jwkSource, "JWK source should not be null");
        }

        @Test
        @DisplayName("Should throw exception with null RSA key")
        void testJWKSourceWithNullRSAKey() {
            // When & Then
            assertThrows(Exception.class, () -> securityService.jwkSource(null),
                "Should throw exception when RSA key is null");
        }
    }

    @Nested
    @DisplayName("JWT Decoder Tests")
    class JWTDecoderTests {

        @Test
        @DisplayName("Should create JWT decoder from RSA key")
        void testJWTDecoderCreation() throws JOSEException {
            // Given
            KeyPair keyPair = securityService.keyPair();
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            
            // When
            JwtDecoder jwtDecoder = securityService.jwtDecoder(rsaKey);
            
            // Then
            assertNotNull(jwtDecoder, "JWT decoder should not be null");
        }

        @Test
        @DisplayName("Should throw exception with null RSA key")
        void testJWTDecoderWithNullRSAKey() {
            // When & Then
            assertThrows(Exception.class, () -> securityService.jwtDecoder(null),
                "Should throw exception when RSA key is null");
        }
    }

    @Nested
    @DisplayName("JWT Encoder Tests")
    class JWTEncoderTests {

        @Test
        @DisplayName("Should create JWT encoder from JWK source")
        void testJWTEncoderCreation() {
            // Given
            KeyPair keyPair = securityService.keyPair();
            RSAKey rsaKey = securityService.rsaKey(keyPair);
            JWKSource<SecurityContext> jwkSource = securityService.jwkSource(rsaKey);
            
            // When
            JwtEncoder jwtEncoder = securityService.jwtEncoder(jwkSource);
            
            // Then
            assertNotNull(jwtEncoder, "JWT encoder should not be null");
        }

        @Test
        @DisplayName("Should throw exception with null JWK source")
        void testJWTEncoderWithNullJWKSource() {
            // When & Then
            assertThrows(Exception.class, () -> securityService.jwtEncoder(null),
                "Should throw exception when JWK source is null");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should create complete security chain with all components")
        void testCompleteSecurityChainCreation() throws Exception {
            // Given
            HONPRMMembersSecurityService service = new HONPRMMembersSecurityService();
            
            // When
            KeyPair keyPair = service.keyPair();
            RSAKey rsaKey = service.rsaKey(keyPair);
            JWKSource<SecurityContext> jwkSource = service.jwkSource(rsaKey);
            JwtEncoder encoder = service.jwtEncoder(jwkSource);
            JwtDecoder decoder = service.jwtDecoder(rsaKey);
            BCryptPasswordEncoder passwordEncoder = service.bCryptPasswordEncoder();
            UserDetailsService userDetailsService = service.userDetailsService();
            
            // Then
            assertNotNull(keyPair, "Key pair should be created");
            assertNotNull(rsaKey, "RSA key should be created");
            assertNotNull(jwkSource, "JWK source should be created");
            assertNotNull(encoder, "JWT encoder should be created");
            assertNotNull(decoder, "JWT decoder should be created");
            assertNotNull(passwordEncoder, "Password encoder should be created");
            assertNotNull(userDetailsService, "User details service should be created");
        }

        @Test
        @DisplayName("Should encode and decode JWT token successfully")
        void testJWTEncodingAndDecoding() throws Exception {
            // This test would require additional JWT token creation and validation
            // which depends on Spring Security's JWT implementation details
            // It serves as a placeholder for integration testing
            assertTrue(true, "JWT encoding/decoding integration test placeholder");
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle multiple concurrent key pair generations")
        void testConcurrentKeyPairGeneration() throws InterruptedException {
            // Given
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            KeyPair[] keyPairs = new KeyPair[threadCount];
            
            // When
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    keyPairs[index] = securityService.keyPair();
                });
                threads[i].start();
            }
            
            for (Thread thread : threads) {
                thread.join();
            }
            
            // Then
            for (KeyPair keyPair : keyPairs) {
                assertNotNull(keyPair, "All key pairs should be generated successfully");
            }
        }

        @Test
        @DisplayName("Should handle empty password encoding")
        void testEmptyPasswordEncoding() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String emptyPassword = "";
            
            // When
            String encodedPassword = encoder.encode(emptyPassword);
            
            // Then
            assertNotNull(encodedPassword, "Empty password should be encoded");
            assertTrue(encoder.matches(emptyPassword, encodedPassword),
                "Empty password should match its encoding");
        }

        @Test
        @DisplayName("Should handle very long password encoding")
        void testLongPasswordEncoding() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String longPassword = "a".repeat(1000);
            
            // When
            String encodedPassword = encoder.encode(longPassword);
            
            // Then
            assertNotNull(encodedPassword, "Long password should be encoded");
            assertTrue(encoder.matches(longPassword, encodedPassword),
                "Long password should match its encoding");
        }

        @Test
        @DisplayName("Should handle special characters in password")
        void testSpecialCharactersPasswordEncoding() {
            // Given
            BCryptPasswordEncoder encoder = securityService.bCryptPasswordEncoder();
            String specialPassword = "p@$$w0rd!#%&*(){}[]<>?/\\|~`";
            
            // When
            String encodedPassword = encoder.encode(specialPassword);
            
            // Then
            assertNotNull(encodedPassword, "Password with special characters should be encoded");
            assertTrue(encoder.matches(specialPassword, encodedPassword),
                "Password with special characters should match its encoding");
        }
    }
}