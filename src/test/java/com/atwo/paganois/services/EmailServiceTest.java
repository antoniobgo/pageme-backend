package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/**
 * Testes unitários para EmailService
 * 
 * Estrutura:
 * - Testes de sendSimpleEmail (envio de email texto puro)
 * - Testes de sendHtmlEmail (envio de email HTML)
 * - Cenários de erro/exceção
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService - Testes Unitários")
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

    @BeforeEach
    void setUp() {
        // Injeta valor do @Value("${spring.mail.username}")
        ReflectionTestUtils.setField(emailService, "fromEmail", FROM_EMAIL);
    }

    // ========================================================================
    // TESTES: sendSimpleEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendSimpleEmail() - Email texto puro")
    class SendSimpleEmailTests {

        @Test
        @DisplayName("Deveria enviar email simples com sucesso quando dados são válidos")
        void deveria_EnviarEmailSimples_QuandoDadosValidos() {
            // Arrange - preparar
            // (nada a preparar, mocks já configurados)

            // Act - executar
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert - verificar
            verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
        }

        @Test
        @DisplayName("Deveria configurar destinatário corretamente")
        void deveria_ConfigurarDestinatario_Corretamente() {
            // Arrange
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getTo())
                    .isNotNull()
                    .hasSize(1)
                    .contains(TO_EMAIL);
        }

        @Test
        @DisplayName("Deveria configurar remetente corretamente")
        void deveria_ConfigurarRemetente_Corretamente() {
            // Arrange
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getFrom()).isEqualTo(FROM_EMAIL);
        }

        @Test
        @DisplayName("Deveria configurar assunto corretamente")
        void deveria_ConfigurarAssunto_Corretamente() {
            // Arrange
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getSubject()).isEqualTo(SUBJECT);
        }

        @Test
        @DisplayName("Deveria configurar corpo do email corretamente")
        void deveria_ConfigurarCorpo_Corretamente() {
            // Arrange
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getText()).isEqualTo(TEXT_CONTENT);
        }

        @Test
        @DisplayName("Deveria configurar todos os campos corretamente em uma única chamada")
        void deveria_ConfigurarTodosCampos_Corretamente() {
            // Arrange
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            SimpleMailMessage sentMessage = messageCaptor.getValue();

            assertThat(sentMessage.getFrom()).isEqualTo(FROM_EMAIL);
            assertThat(sentMessage.getTo()).containsExactly(TO_EMAIL);
            assertThat(sentMessage.getSubject()).isEqualTo(SUBJECT);
            assertThat(sentMessage.getText()).isEqualTo(TEXT_CONTENT);
        }

        @Test
        @DisplayName("Deveria propagar exceção quando JavaMailSender falha")
        void deveria_PropagarExcecao_QuandoMailSenderFalha() {
            // Arrange
            doThrow(new MailSendException("SMTP server error"))
                    .when(mailSender).send(any(SimpleMailMessage.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                    .isInstanceOf(MailSendException.class)
                    .hasMessageContaining("SMTP server error");
        }
    }

    // ========================================================================
    // TESTES: sendHtmlEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendHtmlEmail() - Email HTML")
    class SendHtmlEmailTests {

        private MimeMessage mimeMessage;

        @BeforeEach
        void setUp() {
            // Mock do MimeMessage que JavaMailSender cria
            mimeMessage = mock(MimeMessage.class);
            when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        }

        @Test
        @DisplayName("Deveria criar MimeMessage quando enviar email HTML")
        void deveria_CriarMimeMessage_QuandoEnviarHtml() throws MessagingException {
            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            verify(mailSender, times(1)).createMimeMessage();
        }

        @Test
        @DisplayName("Deveria enviar MimeMessage quando email HTML é válido")
        void deveria_EnviarMimeMessage_QuandoHtmlValido() throws MessagingException {
            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            verify(mailSender, times(1)).send(any(MimeMessage.class));
        }

        @Test
        @DisplayName("Deveria lançar MessagingException quando configuração falha")
        void deveria_LancarMessagingException_QuandoConfiguracaoFalha()
                throws MessagingException {
            // Arrange
            // Simula erro ao configurar MimeMessage
            MimeMessage faultyMessage = mock(MimeMessage.class);
            when(mailSender.createMimeMessage()).thenReturn(faultyMessage);
            doThrow(new MessagingException("Invalid email address"))
                    .when(faultyMessage).setFrom(any(jakarta.mail.internet.InternetAddress.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT))
                    .isInstanceOf(MessagingException.class);
        }

        @Test
        @DisplayName("Deveria propagar exceção quando envio de MimeMessage falha")
        void deveria_PropagarExcecao_QuandoEnvioMimeFalha() {
            // Arrange
            doThrow(new MailSendException("Connection timeout"))
                    .when(mailSender).send(any(MimeMessage.class));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT))
                    .isInstanceOf(MailSendException.class)
                    .hasMessageContaining("Connection timeout");
        }

        @Test
        @DisplayName("Deveria não lançar exceção quando email HTML é enviado com sucesso")
        void deveria_NaoLancarExcecao_QuandoHtmlEnviadoComSucesso() {
            // Act & Assert - não deve lançar exceção
            org.junit.jupiter.api.Assertions
                    .assertDoesNotThrow(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT));
        }
    }

    // ========================================================================
    // TESTES: Cenários de Borda e Validação
    // ========================================================================

    @Nested
    @DisplayName("Cenários de borda e validação")
    class EdgeCasesTests {

        @Test
        @DisplayName("Deveria enviar email com assunto vazio")
        void deveria_EnviarEmail_ComAssuntoVazio() {
            // Arrange
            String emptySubject = "";
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, emptySubject, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getSubject()).isEmpty();
        }

        @Test
        @DisplayName("Deveria enviar email com conteúdo vazio")
        void deveria_EnviarEmail_ComConteudoVazio() {
            // Arrange
            String emptyContent = "";
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, emptyContent);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).isEmpty();
        }

        @Test
        @DisplayName("Deveria enviar email com conteúdo muito longo")
        void deveria_EnviarEmail_ComConteudoLongo() {
            // Arrange
            String longContent = "A".repeat(10000);
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, longContent);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getText()).hasSize(10000);
        }

        @Test
        @DisplayName("Deveria enviar email com caracteres especiais no assunto")
        void deveria_EnviarEmail_ComCaracteresEspeciais() {
            // Arrange
            String specialSubject = "Olá! 你好 🎉 <test>";
            ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, specialSubject, TEXT_CONTENT);

            // Assert
            verify(mailSender).send(messageCaptor.capture());
            assertThat(messageCaptor.getValue().getSubject()).isEqualTo(specialSubject);
        }
    }
}