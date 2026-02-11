package com.atwo.paganois.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;

@Configuration
public class OpenApiConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";

        return new OpenAPI()
                .info(new Info().title("Auth System").version("1.0.0").description("""
                        # Sistema de Autenticação Jwt Simples

                        API RESTful

                        ## Recursos Principais

                        - **Autenticação JWT** com access e refresh tokens
                        - **Verificação de email** obrigatória para ativação de conta
                        - **Rate limiting** por endpoint para proteção contra abuso
                        - **Reset de senha** seguro via email
                        - **Gerenciamento completo** de perfil de usuário
                        - **Mudança de email** com confirmação via token

                        ## Segurança

                        - Senhas hasheadas com **BCrypt**
                        - Tokens JWT assinados com **HMAC-SHA256**
                        - Proteção contra **brute force** com rate limiting
                        - Validação rigorosa de entrada em todos os endpoints
                        - Tokens de uso único para operações sensíveis

                        ## Como Usar

                        1. **Registre-se** via `POST /auth/register`
                        2. **Verifique seu email** (verifique inbox no Mailtrap em dev)
                        3. **Faça login** via `POST /auth/login` para obter tokens
                        4. **Use o access token** no header: `Authorization: Bearer {token}`
                        5. **Renove tokens** via `POST /auth/refresh` quando expirarem (15 min)

                        ## Rate Limits

                        | Endpoint | Limite | Janela |
                        |----------|--------|---------|
                        | Login | 5 req | 1 minuto |
                        | Register | 3 req | 1 hora |
                        | Forgot Password | 3 req | 1 hora |
                        | Resend Verification | 3 req | 1 hora |
                        | Endpoints Gerais | 100 req | 1 minuto |

                        ## Usuário Padrão (com email verificado)

                        | Username | Password | Role |
                        |----------|----------|------|
                        | `user` | `password` | USER |

                        """)
                        .contact(new Contact().name("Antonio Gomes").email("antoniomigom@gmail.com")
                                .url("https://github.com/antoniobgo"))
                        .license(new License().name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))

                .servers(List.of(new Server().url(baseUrl).description("Ambiente de Homologação")))

                .components(
                        new Components()
                                .addSecuritySchemes(securitySchemeName,
                                        new SecurityScheme().name(securitySchemeName)
                                                .type(SecurityScheme.Type.HTTP).scheme("bearer")
                                                .bearerFormat("JWT").description(
                                                        """
                                                                ### Como Autenticar

                                                                1. Faça **POST** em `/auth/login` com username e password
                                                                2. Copie o `accessToken` da resposta
                                                                3. Clique em **"Authorize"** (cadeado no topo)
                                                                4. Cole o token (apenas o valor, sem "Bearer ")
                                                                5. Clique em **"Authorize"** para salvar

                                                                ### Renovação de Token

                                                                O access token expira em **15 minutos**. Quando expirar:
                                                                - Use `POST /auth/refresh` com o `refreshToken`
                                                                - Você receberá novos access e refresh tokens
                                                                - O refresh token expira em **7 dias**
                                                                """))

                                .addSchemas("ErrorResponse", new Schema<>().type("object")
                                        .description("Resposta padrão de erro da API")
                                        .addProperty("timestamp",
                                                new Schema<>().type("string").format("date-time")
                                                        .example("2026-02-11T14:30:00Z"))
                                        .addProperty("status",
                                                new Schema<>().type("integer").example(400))
                                        .addProperty("error",
                                                new Schema<>().type("string")
                                                        .example("Bad Request"))
                                        .addProperty("message",
                                                new Schema<>().type("string")
                                                        .example("Dados inválidos fornecidos"))
                                        .addProperty("path",
                                                new Schema<>().type("string")
                                                        .example("/auth/login"))))

                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName));
    }
}
