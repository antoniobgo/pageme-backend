# Auth System

Sistema de autenticação e autorização RESTful construído com Spring Boot 3 e Spring Security 6, implementando JWT, verificação de email, reset de senha e rate limiting.

[![Java](https://img.shields.io/badge/Java-21-orange?style=flat&logo=openjdk)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.9-brightgreen?style=flat&logo=spring)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

### Link para teste da API via Swagger: 
https://auth-jwt-system.up.railway.app/swagger-ui/index.html


## Índice

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Tecnologias](#tecnologias)
- [Arquitetura](#arquitetura)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Endpoints da API](#endpoints-da-api)
- [Rate Limiting](#rate-limiting)
- [Testes](#testes)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Roadmap](#roadmap)
- [Licença](#licença)
- [Contato](#contato)

## Visão Geral

O Paganois Auth System é uma aplicação completa de autenticação desenvolvida como projeto educacional e de portfólio. O sistema demonstra implementação de padrões de segurança modernos, arquitetura limpa e boas práticas de desenvolvimento com Spring Boot.

### Principais Características

- **Autenticação JWT**: Sistema de tokens com access e refresh tokens
- **Verificação de Email**: Fluxo completo de confirmação de conta
- **Reset de Senha**: Processo seguro de recuperação de senha
- **Alteração de Email**: Mudança de email com verificação
- **Rate Limiting**: Proteção contra força bruta e spam
- **Limpeza Automática**: Remoção de usuários não verificados após 7 dias
- **Documentação Swagger**: Interface interativa da API
- **Testes Unitários**: Alta cobertura de código

## Funcionalidades

### Autenticação e Autorização

- Registro de novos usuários com validação de senha forte
- Login com geração de JWT (access token válido por 15 minutos)
- Refresh token para renovação (válido por 7 dias)
- Controle de acesso baseado em roles (USER, ADMIN)
- Proteção de rotas com Spring Security

### Gerenciamento de Conta

- Verificação de email obrigatória para ativação da conta
- Reenvio de email de verificação
- Solicitação de reset de senha via email
- Reset de senha com token temporário
- Alteração de senha para usuários autenticados
- Solicitação e confirmação de mudança de email

### Segurança

- Hash de senhas com BCrypt
- Tokens JWT assinados com HMAC-SHA256
- Validação de senha forte (mínimo 8 caracteres, maiúsculas, minúsculas, números e caracteres especiais)
- Rate limiting configurável por endpoint
- Limpeza automática de dados sensíveis

### Administração

- Task agendada para remoção de contas não verificadas (executa diariamente às 3h)
- Logs detalhados de autenticação e rate limiting
- Console H2 para inspeção do banco de dados em desenvolvimento

## Tecnologias

### Core

- **Java 21**: Linguagem de programação
- **Spring Boot 3.5.9**: Framework principal
- **Spring Security 6**: Autenticação e autorização
- **Spring Data JPA**: Persistência de dados
- **H2 Database**: Banco de dados em memória para desenvolvimento

### Segurança e Comunicação

- **JJWT 0.12.5**: Geração e validação de JWT
- **BCrypt**: Algoritmo de hash de senhas
- **Spring Mail**: Envio de emails
- **Mailtrap**: Servidor SMTP para testes

### Rate Limiting

- **Bucket4j 8.10.1**: Implementação do algoritmo Token Bucket
- **Caffeine 3.1.8**: Cache em memória de alta performance

### Documentação e Testes

- **SpringDoc OpenAPI 2.8.4**: Documentação Swagger/OpenAPI
- **JUnit 5**: Framework de testes
- **Mockito**: Mocks para testes unitários
- **AssertJ**: Assertions fluentes

### Ferramentas

- **Maven**: Gerenciamento de dependências e build

## Arquitetura

### Componentes Principais

**Controllers**

- `AuthController`: Endpoints públicos de autenticação
- `UserController`: Endpoints protegidos de gerenciamento de usuário

**Services**

- `AuthService`: Orquestra fluxos de autenticação (login, registro, reset)
- `UserService`: Operações de usuário (perfil, senha, email)
- `CustomUserDetailsService`: Integração com Spring Security
- `VerificationService`: Gerencia tokens de verificação
- `EmailService`: Envio de emails (texto e HTML)
- `RateLimitService`: Controle de taxa de requisições

**Security**

- `JwtAuthFilter`: Filtro de autenticação JWT
- `JwtUtil`: Geração e validação de tokens
- `RateLimitFilter`: Filtro de rate limiting
- `SecurityConfig`: Configuração do Spring Security

### Decisões Arquiteturais

1. **Separação de UserDetailsService**: `CustomUserDetailsService` e `UserService` são separados para evitar dependências circulares e manter responsabilidades claras
2. **DTOs para API**: Desacoplamento entre entidades de domínio e contratos da API
3. **Tokens UUID**: Identificadores únicos e seguros para verificações
4. **Password Encoding**: Senha é encodada em `AuthService` antes de ser passada para `UserService`
5. **Rate Limiting em Filtro**: Proteção aplicada antes de qualquer processamento
6. **Cache de Buckets**: Uso de Caffeine para performance em rate limiting

## Pré-requisitos

- Java 21 ou superior
- Maven 3.8+
- Conta no Mailtrap (gratuita) para testes de email: [mailtrap.io](https://mailtrap.io)

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/antoniobgo/paganois.git
cd paganois
```

### 2. Configure as variáveis de ambiente

Edite `src/main/resources/application.properties`:

```properties
# JWT Secret (IMPORTANTE: altere para produção!)
jwt.secret=SUA_CHAVE_SECRETA_BASE64_AQUI

# Mailtrap SMTP
spring.mail.username=SEU_USERNAME_MAILTRAP
spring.mail.password=SUA_SENHA_MAILTRAP

# URL base da aplicação
app.base-url=http://localhost:8080
```

### 3. Compile e execute

```bash
./mvnw clean install
./mvnw spring-boot:run
```

A aplicação estará disponível em: **http://localhost:8080**

## Configuração

### Mailtrap

1. Crie uma conta gratuita em [mailtrap.io](https://mailtrap.io)
2. Crie um novo inbox
3. Copie as credenciais SMTP da seção "Integrations"
4. Atualize o `application.properties`:

```properties
spring.mail.host=sandbox.smtp.mailtrap.io
spring.mail.port=2525
spring.mail.username=SEU_USERNAME
spring.mail.password=SUA_SENHA
```

### JWT

Gere uma chave secreta segura para produção:

```bash
# Linux/Mac
openssl rand -base64 32

# Windows (PowerShell)
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

Atualize no `application.properties`:

```properties
jwt.secret=SUA_CHAVE_GERADA_AQUI
jwt.expiration=900000           # 15 minutos (access token)
jwt.refresh-expiration=604800000 # 7 dias (refresh token)
```

### Rate Limiting

Configure os limites por endpoint no `application.properties`:

```properties
# Login: 5 tentativas por minuto
rate-limit.login.capacity=5
rate-limit.login.refill-tokens=5
rate-limit.login.refill-minutes=1

# Register: 3 registros por hora
rate-limit.register.capacity=3
rate-limit.register.refill-tokens=3
rate-limit.register.refill-minutes=60

# Forgot Password: 3 solicitações por hora
rate-limit.forgot-password.capacity=3
rate-limit.forgot-password.refill-tokens=3
rate-limit.forgot-password.refill-minutes=60
```

### Usuários Padrão

O sistema cria automaticamente dois usuários via `DataLoader`:

| Username | Password           | Role         | Email Verificado |
| -------- | ------------------ | ------------ | ---------------- |
| `user`   | `strong2paSSworD!` | `ROLE_USER`  | Sim              |
| `admin`  | `admin`            | `ROLE_ADMIN` | Sim              |

### H2 Console

Console do banco de dados disponível em: **http://localhost:8080/h2-console**

```
JDBC URL: jdbc:h2:mem:testdb
Username: sa
Password: (deixe vazio)
```

## Endpoints da API

### Documentação Swagger

Acesse a documentação interativa completa:

- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **OpenAPI JSON**: http://localhost:8080/v3/api-docs

### Autenticação (Público)

#### Registrar Usuário

```http
POST /auth/register
Content-Type: application/json

{
  "username": "joaosilva",
  "email": "joao@example.com",
  "password": "S3nh@Fort3!"
}
```

**Resposta 201 Created:**

```json
{
  "id": 1,
  "username": "joaosilva",
  "isEmailVerified": false
}
```

#### Login

```http
POST /auth/login
Content-Type: application/json

{
  "username": "user",
  "password": "strong2paSSworD!"
}
```

**Resposta 200 OK:**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900000
}
```

#### Renovar Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### Verificar Email

```http
GET /auth/verify-email?token={TOKEN_DO_EMAIL}
```

**Resposta 200 OK:**

```json
{
  "message": "Email verificado com sucesso!"
}
```

#### Reenviar Verificação

```http
POST /auth/resend-verification
Content-Type: application/json

{
  "email": "joao@example.com"
}
```

**Resposta 202 Accepted:**

```json
{
  "message": "Se o email existir e não estiver verificado, você receberá um novo link de verificação."
}
```

#### Solicitar Reset de Senha

```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "joao@example.com"
}
```

**Resposta 200 OK:**

```json
{
  "message": "Se o email existir em nosso sistema, você receberá instruções para redefinir sua senha."
}
```

#### Resetar Senha

```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "newPassword": "Nov@S3nh4!"
}
```

**Resposta 204 No Content**

### Usuários (Protegido)

Todos os endpoints abaixo requerem autenticação via Bearer Token.

#### Obter Perfil

```http
GET /api/users/me
Authorization: Bearer {ACCESS_TOKEN}
```

**Resposta 200 OK:**

```json
{
  "id": 1,
  "username": "joaosilva",
  "email": "joao@example.com",
  "role": {
    "id": 1,
    "authority": "ROLE_USER"
  },
  "enabled": true,
  "emailVerified": true
}
```

#### Alterar Senha

```http
POST /api/users/me/password
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json

{
  "oldPassword": "S3nh@Fort3!",
  "newPassword": "Nov@S3nh4!"
}
```

**Resposta 204 No Content**

#### Solicitar Mudança de Email

```http
POST /api/users/me/email
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json

{
  "newEmail": "novoemail@example.com"
}
```

**Resposta 200 OK:**

```json
{
  "message": "Email de confirmação enviado para novoemail@example.com"
}
```

#### Confirmar Mudança de Email

```http
GET /api/users/me/email/confirm?token={TOKEN}
Authorization: Bearer {ACCESS_TOKEN}
```

**Resposta 200 OK:**

```json
{
  "message": "Email alterado com sucesso para novoemail@example.com"
}
```

### Códigos de Status HTTP

| Código | Descrição                                    |
| ------ | -------------------------------------------- |
| 200    | Requisição bem-sucedida                      |
| 201    | Recurso criado com sucesso                   |
| 202    | Requisição aceita (processamento assíncrono) |
| 204    | Sucesso sem conteúdo de resposta             |
| 400    | Requisição inválida (validação falhou)       |
| 401    | Não autenticado (token ausente/inválido)     |
| 403    | Não autorizado (sem permissão)               |
| 404    | Recurso não encontrado                       |
| 409    | Conflito (ex: username/email já existe)      |
| 410    | Token expirado                               |
| 429    | Muitas requisições (rate limit excedido)     |
| 500    | Erro interno do servidor                     |

## Rate Limiting

O sistema implementa rate limiting usando o algoritmo Token Bucket com Bucket4j e cache Caffeine.

### Funcionamento

Cada endereço IP possui um "bucket" de tokens:

- Cada requisição consome 1 token
- Tokens são reabastecidos periodicamente
- Sem tokens disponíveis, a requisição é rejeitada com status 429

### Limites Configurados

| Endpoint                    | Capacidade      | Recarga    | Período  |
| --------------------------- | --------------- | ---------- | -------- |
| `/auth/login`               | 5 requisições   | 5 tokens   | 1 minuto |
| `/auth/register`            | 3 requisições   | 3 tokens   | 1 hora   |
| `/auth/forgot-password`     | 3 requisições   | 3 tokens   | 1 hora   |
| `/auth/resend-verification` | 3 requisições   | 3 tokens   | 1 hora   |
| `/api/**` (geral)           | 100 requisições | 100 tokens | 1 minuto |

### Headers de Resposta

Quando o rate limit é aplicado, a resposta inclui headers informativos:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Remaining: 0
X-RateLimit-Retry-After: 45
Retry-After: 45
Content-Type: application/json

{
  "timestamp": "2026-01-30T12:00:00Z",
  "status": 429,
  "error": "Too Many Requests",
  "message": "Muitas requisições. Tente novamente em 45 segundos.",
  "path": "/auth/login",
  "retryAfterSeconds": 45
}
```

### Detecção de IP

O filtro detecta o IP real do cliente considerando proxies e load balancers, verificando headers na seguinte ordem:

1. `X-Forwarded-For`
2. `X-Real-IP`
3. `Proxy-Client-IP`
4. `WL-Proxy-Client-IP`
5. `HTTP_X_FORWARDED_FOR`
6. `HTTP_CLIENT_IP`
7. `RemoteAddr` (IP direto da conexão)

## Testes

### Executar Testes

```bash
# Executar todos os testes
./mvnw test

# Executar com relatório de cobertura
./mvnw clean test

# Executar teste específico
./mvnw test -Dtest=AuthServiceTest
```

### Cobertura de Código

O projeto possui testes unitários abrangentes para os principais serviços:

- `AuthService`: 100% de cobertura
- `UserService`: 100% de cobertura
- `CustomUserDetailsService`: 100% de cobertura
- `VerificationService`: 100% de cobertura
- `EmailService`: 100% de cobertura

### Estrutura de Testes

```
src/test/java/com/atwo/paganois/
├── services/
│   ├── AuthServiceTest.java
│   ├── UserServiceTest.java
│   ├── CustomUserDetailsServiceTest.java
│   ├── VerificationServiceTest.java
│   └── EmailServiceTest.java
└── PaganoisApplicationTests.java
```

### Padrões de Teste

Os testes seguem o padrão AAA (Arrange-Act-Assert):

```java
@Test
@DisplayName("Should authenticate user and generate tokens")
void shouldAuthenticateUser() {
    // Arrange
    when(authenticationManager.authenticate(any()))
        .thenReturn(authentication);

    // Act
    LoginResponse response = authService.login(loginRequest);

    // Assert
    assertThat(response.accessToken()).isNotNull();
    verify(jwtUtil).generateToken(any());
}
```

## Estrutura do Projeto

```
src/main/java/com/atwo/paganois/
├── config/
│   ├── OpenApiConfig.java          # Configuração do Swagger/OpenAPI
│   ├── RateLimitConfig.java        # Configuração de rate limiting
│   ├── ScheduledTasks.java         # Tasks agendadas
│   └── SecurityConfig.java         # Configuração do Spring Security
├── controllers/
│   ├── AuthController.java         # Endpoints de autenticação
│   ├── UserController.java         # Endpoints de usuário
│   └── handlers/
│       └── GlobalExceptionHandler.java  # Tratamento global de exceções
├── dtos/
│   ├── LoginRequest.java           # Request de login
│   ├── LoginResponse.java          # Response de login
│   ├── RegisterRequest.java        # Request de registro
│   ├── RegisterResponse.java       # Response de registro
│   ├── RefreshRequest.java         # Request de refresh token
│   ├── ResetPasswordRequest.java   # Request de reset de senha
│   ├── ForgotPasswordRequest.java  # Request de esqueci senha
│   ├── ChangeEmailRequest.java     # Request de mudança de email
│   ├── UpdatePasswordRequest.java  # Request de atualização de senha
│   ├── UserDTO.java                # DTO de usuário
│   ├── MessageResponse.java        # Response genérica de mensagem
│   └── CustomErrorResponse.java    # Response de erro customizada
├── entities/
│   ├── User.java                   # Entidade de usuário
│   ├── Role.java                   # Entidade de role
│   ├── VerificationToken.java      # Entidade de token de verificação
│   └── TokenType.java              # Enum de tipos de token
├── exceptions/
│   ├── UserAlreadyExistsException.java
│   ├── UserNotFoundException.java
│   ├── AccountDisabledException.java
│   ├── UserNotVerifiedOrNotEnabledException.java
│   ├── InvalidTokenException.java
│   ├── TokenNotFoundException.java
│   ├── ExpiredTokenException.java
│   ├── InvalidTokenTypeException.java
│   ├── WrongPasswordException.java
│   ├── EmailAlreadyTakenException.java
│   └── LoggedUserAndChangeEmailTokenMismatchException.java
├── repositories/
│   ├── UserRepository.java         # Repositório de usuários
│   ├── RoleRepository.java         # Repositório de roles
│   └── VerificationTokenRepository.java  # Repositório de tokens
├── security/
│   ├── JwtAuthFilter.java          # Filtro de autenticação JWT
│   ├── JwtUtil.java                # Utilitário JWT
│   └── RateLimitFilter.java        # Filtro de rate limiting
├── services/
│   ├── AuthService.java            # Serviço de autenticação
│   ├── UserService.java            # Serviço de usuário
│   ├── CustomUserDetailsService.java    # UserDetailsService customizado
│   ├── VerificationService.java    # Serviço de verificação
│   ├── EmailService.java           # Serviço de email
│   └── RateLimitService.java       # Serviço de rate limiting
├── validators/
│   ├── StrongPassword.java         # Anotação de validação de senha
│   └── StrongPasswordValidator.java # Validador de senha forte
├── DataLoader.java                 # Carregador de dados iniciais
└── PaganoisApplication.java        # Classe principal
```

## Roadmap

### Funcionalidades Planejadas

#### Autenticação e Segurança

- OAuth2/Social Login (Google, GitHub, Facebook)
- Two-Factor Authentication (2FA via TOTP)
- Biometric authentication support
- Session management e revogação de tokens
- Blacklist de tokens JWT
- HTTPS obrigatório em produção
- CORS configurável

#### Infraestrutura

- Docker e Docker Compose
- Migração para PostgreSQL em produção
- Redis para cache de tokens e sessões
- Kubernetes deployment configuration
- CI/CD com GitHub Actions
- Health checks e readiness probes

#### Observabilidade

- Spring Boot Actuator
- Métricas customizadas com Micrometer
- Integração com Prometheus
- Dashboards no Grafana
- Distributed tracing com Sleuth/Zipkin
- Audit log completo

#### API e Documentação

- API Versioning (`/api/v1/`, `/api/v2/`)
- Webhooks para eventos importantes
- GraphQL endpoint
- Postman collection
- Documentação técnica detalhada

#### Database e Persistência

- Flyway ou Liquibase para migrations
- Índices otimizados
- Particionamento de tabelas
- Backup automatizado
- Read replicas

#### Testing

- Testes de integração (`@SpringBootTest`, `@WebMvcTest`)
- Testes de contrato (Spring Cloud Contract)
- Testes de performance (JMeter, Gatling)
- Mutation testing (PIT)
- E2E tests

#### Melhorias de Código

- Soft delete para usuários
- Email templates com Thymeleaf
- Internacionalização (i18n)
- Paginação e ordenação em listagens
- Filtros e busca avançada
- Upload de avatar
- Logs estruturados (JSON)

### Sugestões de Melhorias Técnicas

**Validação e Input**

- Adicionar mais validações customizadas nos DTOs
- Implementar sanitização de input
- Validador de força de senha mais robusto
- Verificação de email descartável

**Exception Handling**

- Centralizar todas as exceções no GlobalExceptionHandler
- Padronizar respostas de erro
- Adicionar error codes únicos
- Melhorar mensagens de erro para o usuário

**Performance**

- Implementar cache com Redis
- Connection pooling otimizado (HikariCP)
- Lazy loading configurado adequadamente
- Query optimization
- Índices de banco de dados

**Monitoramento**

- Application Performance Monitoring (APM)
- Error tracking (Sentry, Rollbar)
- Log aggregation (ELK Stack)
- Alertas automatizados

**Deployment**

- Blue-green deployment
- Canary releases
- Feature flags
- Database migrations automáticas
- Rollback automatizado

## Licença

Este projeto está licenciado sob a Licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contato

**Antonio Gomes**

- Email: antoniomigom@gmail.com
- GitHub: [@antoniobgo](https://github.com/antoniobgo)
- LinkedIn: [Antonio Gomes](https://linkedin.com/in/antoniobgo)

---

Desenvolvido com dedicação como projeto educacional e de portfólio.
