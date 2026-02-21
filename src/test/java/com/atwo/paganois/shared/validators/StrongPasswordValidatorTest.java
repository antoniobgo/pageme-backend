package com.atwo.paganois.shared.validators;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Unit tests for StrongPasswordValidator
 * 
 * CRITICAL SECURITY COMPONENT - Password validation
 * 
 * Pattern: ^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$
 * 
 * Requirements: - Minimum 8 characters - At least 1 lowercase letter - At least 1 uppercase letter
 * - At least 1 digit - At least 1 special character (@$!%*?&#)
 */
@DisplayName("StrongPasswordValidator - Unit Tests")
class StrongPasswordValidatorTest {

    private StrongPasswordValidator validator;
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        validator = new StrongPasswordValidator();
        context = null; // Não usado pela implementação atual
    }

    // ========================================================================
    // TESTS: Valid passwords
    // ========================================================================

    @Nested
    @DisplayName("Senhas válidas")
    class ValidPasswordTests {

        @Test
        @DisplayName("Deveria aceitar senha com todos os requisitos")
        void shouldAccept_PasswordWithAllRequirements() {
            // Arrange
            String password = "Test@123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria aceitar senha com 8 caracteres exatos")
        void shouldAccept_PasswordWith8Characters() {
            // Arrange
            String password = "Pass@123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria aceitar senha longa")
        void shouldAccept_LongPassword() {
            // Arrange
            String password = "SuperSecurePassword@2024!";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria aceitar todos os caracteres especiais permitidos")
        void shouldAccept_AllAllowedSpecialCharacters() {
            // Arrange - Testa cada caractere especial permitido
            String[] passwords = {"Test@123", "Test$123", "Test!123", "Test%123", "Test*123",
                    "Test?123", "Test&123", "Test#123"};

            // Act & Assert
            for (String password : passwords) {
                boolean isValid = validator.isValid(password, context);
                assertThat(isValid).withFailMessage("Senha '%s' deveria ser válida", password)
                        .isTrue();
            }
        }

        @Test
        @DisplayName("Deveria aceitar senha com múltiplos caracteres especiais")
        void shouldAccept_MultipleSpecialCharacters() {
            // Arrange
            String password = "Test@!#$123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria aceitar senha com múltiplas maiúsculas e minúsculas")
        void shouldAccept_MultipleUpperAndLowerCase() {
            // Arrange
            String password = "TeSt@123PaSs";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Deveria aceitar senha com múltiplos números")
        void shouldAccept_MultipleDigits() {
            // Arrange
            String password = "Test@123456";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }
    }

    // ========================================================================
    // TESTS: Invalid passwords - Missing requirements
    // ========================================================================

    @Nested
    @DisplayName("Senhas inválidas - Requisitos faltando")
    class InvalidPasswordMissingRequirementsTests {

        @Test
        @DisplayName("Deveria rejeitar senha sem letra minúscula")
        void shouldReject_PasswordWithoutLowercase() {
            // Arrange
            String password = "TEST@123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha sem letra maiúscula")
        void shouldReject_PasswordWithoutUppercase() {
            // Arrange
            String password = "test@123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha sem número")
        void shouldReject_PasswordWithoutDigit() {
            // Arrange
            String password = "Test@abc";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha sem caractere especial")
        void shouldReject_PasswordWithoutSpecialCharacter() {
            // Arrange
            String password = "Test1234";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha com menos de 8 caracteres")
        void shouldReject_PasswordWithLessThan8Characters() {
            // Arrange
            String password = "Ts@1";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha com exatamente 7 caracteres")
        void shouldReject_PasswordWith7Characters() {
            // Arrange
            String password = "Test@12";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }
    }

    // ========================================================================
    // TESTS: Invalid passwords - Edge cases
    // ========================================================================

    @Nested
    @DisplayName("Senhas inválidas - Casos extremos")
    class InvalidPasswordEdgeCasesTests {

        @Test
        @DisplayName("Deveria rejeitar senha null")
        void shouldReject_NullPassword() {
            // Arrange
            String password = null;

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha vazia")
        void shouldReject_EmptyPassword() {
            // Arrange
            String password = "";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha com apenas espaços")
        void shouldReject_PasswordWithOnlySpaces() {
            // Arrange
            String password = "        ";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha com espaços no meio")
        void shouldReject_PasswordWithSpaces() {
            // Arrange
            String password = "Test @123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha com caracteres especiais não permitidos")
        void shouldReject_PasswordWithDisallowedSpecialCharacters() {
            // Arrange - Caracteres especiais NÃO permitidos
            String[] passwords = {"Test+123", // + não permitido
                    "Test-123", // - não permitido
                    "Test_123", // _ não permitido
                    "Test=123", // = não permitido
                    "Test[123", // [ não permitido
                    "Test]123", // ] não permitido
                    "Test{123", // { não permitido
                    "Test}123", // } não permitido
                    "Test|123", // | não permitido
                    "Test\\123", // \ não permitido
                    "Test/123", // / não permitido
                    "Test:123", // : não permitido
                    "Test;123", // ; não permitido
                    "Test'123", // ' não permitido
                    "Test\"123", // " não permitido
                    "Test<123", // < não permitido
                    "Test>123", // > não permitido
                    "Test,123", // , não permitido
                    "Test.123" // . não permitido
            };

            // Act & Assert
            for (String password : passwords) {
                boolean isValid = validator.isValid(password, context);
                assertThat(isValid).withFailMessage(
                        "Senha '%s' deveria ser inválida (caractere não permitido)", password)
                        .isFalse();
            }
        }
    }

    // ========================================================================
    // TESTS: Common weak passwords
    // ========================================================================

    @Nested
    @DisplayName("Senhas comuns fracas")
    class CommonWeakPasswordsTests {

        @Test
        @DisplayName("Deveria rejeitar senha comum: 'password'")
        void shouldReject_CommonPassword_password() {
            // Arrange
            String password = "password";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha comum: '12345678'")
        void shouldReject_CommonPassword_12345678() {
            // Arrange
            String password = "12345678";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria rejeitar senha comum: 'admin123'")
        void shouldReject_CommonPassword_admin123() {
            // Arrange
            String password = "admin123";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Deveria aceitar senha comum se tiver requisitos: 'Password@1'")
        void shouldAccept_CommonPasswordWithRequirements() {
            // Arrange - Senha comum MAS atende requisitos
            String password = "Password@1";

            // Act
            boolean isValid = validator.isValid(password, context);

            // Assert
            assertThat(isValid).isTrue();
        }
    }

    // ========================================================================
    // TESTS: Real-world scenarios
    // ========================================================================

    @Nested
    @DisplayName("Cenários do mundo real")
    class RealWorldScenariosTests {

        @Test
        @DisplayName("Deveria aceitar senhas típicas de usuários reais")
        void shouldAccept_TypicalUserPasswords() {
            // Arrange - Senhas que usuários reais criariam
            String[] passwords = {"MyP@ssw0rd", "S3cur3P@ss", "Welcome@2024", "Test!ng123",
                    "Admin@123", "User#2024"};

            // Act & Assert
            for (String password : passwords) {
                boolean isValid = validator.isValid(password, context);
                assertThat(isValid).withFailMessage("Senha válida '%s' foi rejeitada", password)
                        .isTrue();
            }
        }

        @Test
        @DisplayName("Deveria rejeitar tentativas comuns de senhas fracas")
        void shouldReject_CommonWeakAttempts() {
            // Arrange - Tentativas comuns de criar senha
            String[] passwords = {"abc123", // Muito curta
                    "ABCDEFGH", // Sem número, minúscula, especial
                    "abcdefgh", // Sem maiúscula, número, especial
                    "12345678", // Sem letras, especial
                    "Test1234", // Sem caractere especial
                    "test@abc", // Sem maiúscula, número
                    "TEST@123", // Sem minúscula
                    "Test@abc" // Sem número
            };

            // Act & Assert
            for (String password : passwords) {
                boolean isValid = validator.isValid(password, context);
                assertThat(isValid).withFailMessage("Senha fraca '%s' foi aceita", password)
                        .isFalse();
            }
        }
    }
}
