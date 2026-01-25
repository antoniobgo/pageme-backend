package com.atwo.paganois.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.Components;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        // Define o esquema de segurança JWT
        final String securitySchemeName = "bearerAuth";

        return new OpenAPI()
                // Informações da API
                .info(new Info()
                        .title("Paganois API")
                        .version("1.0.0")
                        .description("API para sistema de divisão e controle de despesas compartilhadas")
                        .contact(new Contact()
                                .name("Antonio Gomes")
                                .email("antoniomigom@gmail.com")
                                .url("https://github.com/antoniobgo"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))

                // Servidores
                .servers(List.of(
                        new Server()
                                .url(baseUrl)
                                .description("Servidor de Desenvolvimento")))

                // Configuração de segurança JWT
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Insira o access token gerado no endpoint /auth/login")))

                // Aplica segurança globalmente (pode ser sobrescrito por endpoint)
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName));
    }
}