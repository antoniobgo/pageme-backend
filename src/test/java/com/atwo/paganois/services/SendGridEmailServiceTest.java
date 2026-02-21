package com.atwo.paganois.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.test.util.ReflectionTestUtils;
import com.atwo.paganois.email.services.SendGridEmailService;
import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;

/**
 * Unit tests for SendGridEmailService
 * 
 * Structure: - Tests for sendSimpleEmail (plain text email via SendGrid) - Tests for sendHtmlEmail
 * (HTML email via SendGrid) - Error/exception scenarios with SendGrid API - Edge cases and
 * validation
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SendGridEmailService - Unit Tests")
class SendGridEmailServiceTest {

    @Mock
    private SendGrid sendGrid;

    private SendGridEmailService emailService;

    private static final String API_KEY = "test-api-key";
    private static final String FROM_EMAIL = "noreply@paganois.com";
    private static final String TO_EMAIL = "user@example.com";
    private static final String SUBJECT = "Test Subject";
    private static final String TEXT_CONTENT = "Test email content";
    private static final String HTML_CONTENT = "<h1>Test HTML</h1>";
    private static final String SENDGRID_ERROR_MSG = "SendGrid API Error";
    private static final String IO_ERROR_MSG = "Network error";

    @BeforeEach
    void setUp() {
        // Cria o serviço manualmente para poder injetar o mock
        emailService = new SendGridEmailService(API_KEY, FROM_EMAIL);

        // Injeta o SendGrid mockado via reflexão
        ReflectionTestUtils.setField(emailService, "sendGrid", sendGrid);
    }

    // ========================================================================
    // TESTS: sendSimpleEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendSimpleEmail() - Email texto puro via SendGrid")
    class SendSimpleEmailTests {

        private Request captureRequest() throws IOException {
            ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
            verify(sendGrid).api(captor.capture());
            return captor.getValue();
        }

        @Test
        @DisplayName("Deveria enviar email simples com sucesso quando SendGrid retorna 200")
        void shouldSendSimpleEmailSuccessfully_WhenSendGridReturns200() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            verify(sendGrid).api(any(Request.class));
        }

        @Test
        @DisplayName("Deveria configurar Request com método POST correto")
        void shouldConfigureRequest_WithCorrectPostMethod() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            Request request = captureRequest();
            assertThat(request.getMethod()).isEqualTo(Method.POST);
        }

        @Test
        @DisplayName("Deveria configurar Request com endpoint correto")
        void shouldConfigureRequest_WithCorrectEndpoint() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            Request request = captureRequest();
            assertThat(request.getEndpoint()).isEqualTo("mail/send");
        }

        @Test
        @DisplayName("Deveria configurar Request com body contendo dados do email")
        void shouldConfigureRequest_WithEmailDataInBody() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT);

            // Assert
            Request request = captureRequest();
            String body = request.getBody();

            assertThat(body).isNotNull();
            assertThat(body).contains(TO_EMAIL);
            assertThat(body).contains(FROM_EMAIL);
            assertThat(body).contains(SUBJECT);
            assertThat(body).contains(TEXT_CONTENT);
            assertThat(body).contains("text/plain");
        }

        @Test
        @DisplayName("Deveria lançar MailSendException quando SendGrid retorna erro 4xx")
        void shouldThrowMailSendException_WhenSendGridReturns4xx() throws IOException {
            // Arrange
            Response mockResponse = createErrorResponse(400, SENDGRID_ERROR_MSG);
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                    .isInstanceOf(MailSendException.class).hasMessageContaining("SendGrid error");
        }

        @Test
        @DisplayName("Deveria lançar MailSendException quando SendGrid retorna erro 5xx")
        void shouldThrowMailSendException_WhenSendGridReturns5xx() throws IOException {
            // Arrange
            Response mockResponse = createErrorResponse(500, "Internal Server Error");
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                    .isInstanceOf(MailSendException.class).hasMessageContaining("SendGrid error");
        }

        @Test
        @DisplayName("Deveria lançar MailSendException quando ocorre IOException")
        void shouldThrowMailSendException_WhenIOExceptionOccurs() throws IOException {
            // Arrange
            when(sendGrid.api(any(Request.class))).thenThrow(new IOException(IO_ERROR_MSG));

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                    .isInstanceOf(MailSendException.class)
                    .hasMessageContaining("Failed to send email")
                    .hasCauseInstanceOf(IOException.class);
        }
    }

    // ========================================================================
    // TESTS: sendHtmlEmail()
    // ========================================================================

    @Nested
    @DisplayName("sendHtmlEmail() - Email HTML via SendGrid")
    class SendHtmlEmailTests {

        private Request captureRequest() throws IOException {
            ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
            verify(sendGrid).api(captor.capture());
            return captor.getValue();
        }

        @Test
        @DisplayName("Deveria enviar email HTML com sucesso quando SendGrid retorna 200")
        void shouldSendHtmlEmailSuccessfully_WhenSendGridReturns200() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            verify(sendGrid).api(any(Request.class));
        }

        @Test
        @DisplayName("Deveria configurar Request com content-type text/html")
        void shouldConfigureRequest_WithHtmlContentType() throws IOException {
            // Arrange
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act
            emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT);

            // Assert
            Request request = captureRequest();
            String body = request.getBody();

            assertThat(body).contains("text/html");
            assertThat(body).contains(HTML_CONTENT);
        }

        @Test
        @DisplayName("Deveria lançar MailSendException quando SendGrid retorna erro")
        void shouldThrowMailSendException_WhenSendGridReturnsError() throws IOException {
            // Arrange
            Response mockResponse = createErrorResponse(401, "Unauthorized");
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            assertThatThrownBy(() -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, HTML_CONTENT))
                    .isInstanceOf(MailSendException.class).hasMessageContaining("SendGrid error");
        }

        @Test
        @DisplayName("Deveria aceitar HTML complexo com múltiplas tags")
        void shouldAcceptComplexHtml_WithMultipleTags() throws IOException {
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
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendHtmlEmail(TO_EMAIL, SUBJECT, complexHtml));
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
        void shouldAcceptEmail_WithSpecialCharactersInSubject() throws IOException {
            // Arrange
            String specialSubject = "Test: 你好 & Привет! #123 @user";
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendSimpleEmail(TO_EMAIL, specialSubject, TEXT_CONTENT));
        }

        @Test
        @DisplayName("Deveria aceitar conteúdo vazio no corpo do email")
        void shouldAcceptEmptyContent_InEmailBody() throws IOException {
            // Arrange
            String emptyContent = "";
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, emptyContent));
        }

        @Test
        @DisplayName("Deveria aceitar conteúdo com caracteres unicode")
        void shouldAcceptContent_WithUnicodeCharacters() throws IOException {
            // Arrange
            String unicodeContent = "Hello 世界 🌍 Привет مرحبا";
            Response mockResponse = createSuccessResponse();
            when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

            // Act & Assert
            org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                    () -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, unicodeContent));
        }

        @Test
        @DisplayName("Deveria funcionar com diferentes status codes de sucesso")
        void shouldWorkWith_DifferentSuccessStatusCodes() throws IOException {
            // 200, 201, 202 são todos sucesso
            for (int statusCode : new int[] {200, 201, 202}) {
                // Arrange
                Response mockResponse = mock(Response.class);
                when(mockResponse.getStatusCode()).thenReturn(statusCode);
                when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

                // Act & Assert
                org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                        () -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT),
                        "Status code " + statusCode + " should be considered success");
            }
        }

        @Test
        @DisplayName("Deveria falhar com qualquer status code >= 400")
        void shouldFail_WithAnyStatusCodeAbove400() throws IOException {
            // 400, 401, 403, 404, 500, 502, 503
            for (int statusCode : new int[] {400, 401, 403, 404, 500, 502, 503}) {
                // Arrange
                Response mockResponse = createErrorResponse(statusCode, "Error");
                when(sendGrid.api(any(Request.class))).thenReturn(mockResponse);

                // Act & Assert
                assertThatThrownBy(
                        () -> emailService.sendSimpleEmail(TO_EMAIL, SUBJECT, TEXT_CONTENT))
                                .isInstanceOf(MailSendException.class)
                                .as("Status code %d should throw exception", statusCode);
            }
        }
    }

    // ========================================================================
    // Helper methods
    // ========================================================================

    private Response createSuccessResponse() {
        Response response = mock(Response.class);
        when(response.getStatusCode()).thenReturn(200);
        // Não mocka getBody() - será mockado apenas quando necessário
        return response;
    }

    private Response createErrorResponse(int statusCode, String errorMessage) {
        Response response = mock(Response.class);
        when(response.getStatusCode()).thenReturn(statusCode);
        when(response.getBody())
                .thenReturn(String.format("{\"errors\": [{\"message\": \"%s\"}]}", errorMessage));
        return response;
    }
}
