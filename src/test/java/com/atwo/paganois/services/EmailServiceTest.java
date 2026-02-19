package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.email.services.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/**
 * Unit tests for EmailService
 * 
 * Structure: - Tests for sendSimpleEmail (plain text email) - Tests for sendHtmlEmail (HTML email)
 * - Error/exception scenarios
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService - Unit Tests")
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private EmailService emailService;

    private static final String FROM_EMAIL = "noreply@paganois.com";
    private static final String TO_EMAIL = "user@example.com";
    private static final String SUBJECT = "Test Subject";
    private static final String TEXT_CONTENT = "Test email content";
    private static final String HTML_CONTENT = "<h1>Test HTML</h1>";
    private static final String SMTP_ERROR_MSG = "SMTP server error";
    private static final String CONNECTION_TIMEOUT_MSG = "Connection timeout";
    private static final String INVALID_EMAIL_MSG = "Invalid email address";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(emailService, "fromEmail", FROM_EMAIL);
    }

    // ========================================================================
    // TESTS: sendSimpleEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendSimpleEmail() - Email texto puro")
    class SendSimpleEmailTests {

        private SimpleMailMessage captureSimpleMessage() {
            ArgumentCaptor<SimpleMailMessage> captor =
                    ArgumentCaptor.forClass(SimpleMailMessage.class);
            verify(mailSender).send(captor.capture());
            return captor.getValue();
        }

        @Test
        @DisplayName("Deveria enviar email simples com sucesso quando dados são válidos")
        void shouldSendSimpleEmailSuccessfully_WhenDataIsValid() {
            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(any(SimpleMailMessage.class));
        }

        @Test
        @DisplayName("Deveria configurar todos os campos corretamente em uma única chamada")
        void shouldConfigureAllFieldsCorrectly_InSingleCall() {
            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            SimpleMailMessage message = captureSimpleMessage();
            assertThat(message.getFrom()).isEqualTo(FROM_EMAIL);
            assertThat(message.getTo()).containsExactly(TO_EMAIL);
            assertThat(message.getSubject()).isEqualTo(SUBJECT);
            assertThat(message.getText()).isEqualTo(TEXT_CONTENT);
        }

        @Test
        @DisplayName("Deveria propagar exceção quando JavaMailSender falha")
        void shouldPropagateException_WhenMailSenderFails() {
            // Arrange
            doThrow(new MailSendException(SMTP_ERROR_MSG)).when(mailSender)
                    .send(any(SimpleMailMessage.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                    .isInstanceOf(MailSendException.class).hasMessageContaining(SMTP_ERROR_MSG);
        }
    }

    // ========================================================================
    // TESTS: sendHtmlEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendHtmlEmail() - Email HTML")
    class SendHtmlEmailTests {

        private MimeMessage mimeMessage;

        @BeforeEach
        void setUpMimeMessage() {
            mimeMessage = mock(MimeMessage.class);
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        }

        @Test
        @DisplayName("Deveria criar MimeMessage quando enviar email HTML")
        void shouldCreateMimeMessage_WhenSendingHtmlEmail() throws MessagingException {
            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            verify(mailSender).createMimeMessage();
        }

        @Test
        @DisplayName("Deveria enviar MimeMessage quando email HTML é válido")
        void shouldSendMimeMessage_WhenHtmlEmailIsValid() throws MessagingException {
            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            verify(mailSender).send(any(MimeMessage.class));
        }

        @Test
        @DisplayName("Deveria lançar MessagingException quando configuração falha")
        void shouldThrowMessagingException_WhenConfigurationFails() throws MessagingException {
            // Arrange
            MimeMessage faultyMessage = mock(MimeMessage.class);
            when(mailSender.createMimeMessage()).thenReturn(faultyMessage);
            doThrow(new MessagingException(INVALID_EMAIL_MSG)).when(faultyMessage)
                    .setFrom(any(jakarta.mail.internet.InternetAddress.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT))
                    .isInstanceOf(MessagingException.class);
        }

        @Test
        @DisplayName("Deveria propagar exceção quando envio de MimeMessage falha")
        void shouldPropagateException_WhenMimeMessageSendFails() {
            // Arrange
            doThrow(new MailSendException(CONNECTION_TIMEOUT_MSG)).when(mailSender)
                    .send(any(MimeMessage.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT))
                    .isInstanceOf(MailSendException.class)
                    .hasMessageContaining(CONNECTION_TIMEOUT_MSG);
        }

        @Test
        @DisplayName("Deveria não lançar exceção quando email HTML é enviado com sucesso")
        void shouldNotThrowException_WhenHtmlEmailSentSuccessfully() {
            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT));
        }
    }

    // ========================================================================
    // TESTS: Edge cases and validation
    // ========================================================================

    @Nested
    @DisplayName("Cenários de borda e validação")
    class EdgeCasesAndValidationTests {

        @Test
        @DisplayName("Deveria aceitar email com múltiplos caracteres especiais no assunto")
        void shouldAcceptEmailWithSpecialCharactersInSubject() {
            // Arrange
            String specialSubject = "Test: 你好 & Привет! #123 @user";
            ArgumentCaptor<SimpleMailMessage> captor =
                    ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, specialSubject, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(captor.capture());
            assertThat(captor.getValue().getSubject()).isEqualTo(specialSubject);
        }

        @Test
        @DisplayName("Deveria aceitar conteúdo vazio no corpo do email")
        void shouldAcceptEmptyContentInEmailBody() {
            // Arrange
            String emptyContent = "";
            ArgumentCaptor<SimpleMailMessage> captor =
                    ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, emptyContent);

            // Assert
            verify(mailSender).send(captor.capture());
            assertThat(captor.getValue().getText()).isEqualTo(emptyContent);
        }

        @Test
        @DisplayName("Deveria aceitar conteúdo HTML complexo com múltiplas tags")
        void shouldAcceptComplexHtmlContentWithMultipleTags() throws MessagingException {
            // Arrange
            String complexHtml = """
                    <html>
                        <body>
                            <h1>Title</h1>
                            <p>Paragraph with <strong>bold</strong> and <em>italic</em></p>
                            <ul><li>Item 1</li><li>Item 2</li></ul>
                        </body>
                    </html>
                    """;
            MimeMessage mimeMessage = mock(MimeMessage.class);
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);

            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, complexHtml));
        }

        @Test
        @DisplayName("Deveria aceitar conteúdo com caracteres unicode")
        void shouldAcceptContentWithUnicodeCharacters() {
            // Arrange
            String unicodeContent = "Hello 世界 🌍 Привет مرحبا";
            ArgumentCaptor<SimpleMailMessage> captor =
                    ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, unicodeContent);

            // Assert
            verify(mailSender).send(captor.capture());
            assertThat(captor.getValue().getText()).isEqualTo(unicodeContent);
        }
    }
}
