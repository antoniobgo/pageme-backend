# 🔐 Paganois Auth System

Sistema de autenticação e autorização de usuários via JWT utilizando Spring Boot 3 e Spring Security 6.

> **Projeto desenvolvido para fins educacionais e de portfólio**

[![Java](https://img.shields.io/badge/Java-21-orange?style=flat&logo=openjdk)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.9-brightgreen?style=flat&logo=spring)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Tecnologias](#-tecnologias)
- [Arquitetura](#-arquitetura)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Endpoints da API](#-endpoints-da-api)
- [Testes](#-testes)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Roadmap](#-roadmap)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)
- [Contato](#-contato)

## 🎯 Sobre o Projeto

Sistema completo de autenticação RESTful construído com Spring Boot 3, implementando as melhores práticas de segurança e arquitetura de software. O projeto demonstra conhecimentos em:

- 🔒 **Segurança**: JWT (Access + Refresh Tokens), bcrypt password encoding
- 📧 **Comunicação**: Sistema de envio de emails (verificação e reset de senha)
- 🏗️ **Arquitetura**: Separação clara de responsabilidades (Services, Controllers, DTOs)
- ✅ **Qualidade**: Testes unitários com alta cobertura
- 📚 **Documentação**: Swagger/OpenAPI integrado

## ✨ Funcionalidades

- ✅ Registro de novos usuários
- ✅ Login com geração de JWT (access + refresh token)
- ✅ Renovação de token (refresh token flow)
- ✅ Confirmação de email com token único
- ✅ Solicitação de reset de senha
- ✅ Reset de senha via token
- ✅ Controle de acesso baseado em roles (USER, ADMIN)
- ✅ Perfil de usuário autenticado
- ✅ Documentação Swagger/OpenAPI
- ✅ Testes unitários com alta cobertura

## 🛠️ Tecnologias

### Core
- **Java 21** - Linguagem de programação
- **Spring Boot 3.5.9** - Framework principal
- **Spring Security 6** - Autenticação e autorização
- **Spring Data JPA** - Persistência de dados
- **H2 Database** - Banco de dados em memória

### Segurança e Comunicação
- **JWT (jjwt 0.12.5)** - JSON Web Tokens
- **BCrypt** - Hash de senhas
- **Spring Mail** - Envio de emails
- **Mailtrap** - Servidor SMTP para desenvolvimento

### Documentação e Testes
- **SpringDoc OpenAPI 2.3.0** - Documentação Swagger
- **JUnit 5** - Framework de testes
- **Mockito** - Mocks para testes unitários
- **AssertJ** - Assertions fluentes
- **JaCoCo** - Cobertura de código

### Ferramentas
- **Maven** - Gerenciamento de dependências
- **Lombok** (opcional) - Redução de boilerplate

## 🏛️ Arquitetura

O projeto segue uma arquitetura em camadas com separação clara de responsabilidades:

```
┌─────────────────────────────────────────┐
│          Controllers Layer              │
│  (REST API endpoints, validação input)  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│           Services Layer                │
│  (Lógica de negócio, orquestração)      │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         Repositories Layer              │
│      (Acesso a dados via JPA)           │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│          Database (H2)                  │
└─────────────────────────────────────────┘
```

### Principais Services

- **`AuthService`**: Gerencia fluxos de autenticação (login, registro, reset senha)
- **`UserService`**: Operações CRUD de usuários
- **`CustomUserDetailsService`**: Carrega usuários para Spring Security
- **`VerificationService`**: Gerencia tokens de verificação (email, reset)
- **`EmailService`**: Envio de emails (simples e HTML)

### Decisões Arquiteturais

1. **Separação de UserDetailsService e UserService**: Evita dependência circular e mantém responsabilidades claras
2. **DTOs para requests/responses**: Desacoplamento entre API e entidades
3. **Tokens em UUID**: Identificadores únicos e seguros
4. **Senha pré-encodada nos services**: `UserService` recebe senha já codificada do `AuthService`

## 📦 Pré-requisitos

- Java 21 ou superior
- Maven 3.8+
- Conta no Mailtrap (gratuita) - [mailtrap.io](https://mailtrap.io)

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/antoniobgo/paganois.git
cd paganois
```

### 2. Configure as variáveis de ambiente (opcional)

Crie um arquivo `.env` ou configure diretamente no `application.properties`:

```properties
# JWT Secret (gere uma chave segura)
jwt.secret=SUA_CHAVE_SECRETA_BASE64_AQUI

# Mailtrap (obtenha em mailtrap.io)
spring.mail.username=SEU_USERNAME_MAILTRAP
spring.mail.password=SUA_SENHA_MAILTRAP
```

### 3. Compile e execute

```bash
./mvnw clean install
./mvnw spring-boot:run
```

A aplicação estará disponível em: **http://localhost:8080**

## ⚙️ Configuração

### Configuração do Mailtrap

1. Acesse [mailtrap.io](https://mailtrap.io) e crie uma conta gratuita
2. Crie um novo inbox
3. Copie as credenciais SMTP
4. Atualize o `application.properties`:

```properties
spring.mail.host=sandbox.smtp.mailtrap.io
spring.mail.port=2525
spring.mail.username=SEU_USERNAME  # ← Altere aqui
spring.mail.password=SUA_SENHA     # ← Altere aqui
```

### Usuários Padrão

O sistema cria automaticamente dois usuários via `DataLoader`:

| Username | Password | Role |
|----------|----------|------|
| `user` | `password` | `ROLE_USER` |
| `admin` | `admin` | `ROLE_ADMIN` |

### Configuração do JWT

```properties
jwt.secret=uuDCks6U7OIeEVnKigOa24bAcgUldzBU/U7QNBbcTEE=  # Altere para produção
jwt.expiration=900000           # 15 minutos (access token)
jwt.refresh-expiration=604800000 # 7 dias (refresh token)
```

> ⚠️ **IMPORTANTE**: Gere uma nova chave secreta para produção!

```bash
# Gerar chave segura (Linux/Mac)
openssl rand -base64 32
```

### H2 Console

Acesse o console do H2 em: **http://localhost:8080/h2-console**

```
JDBC URL: jdbc:h2:mem:testdb
Username: sa
Password: (deixe vazio)
```

## 📡 Endpoints da API

### Documentação Swagger

Acesse a documentação interativa em:
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **OpenAPI JSON**: http://localhost:8080/v3/api-docs

### Autenticação

#### Registrar Usuário
```http
POST /auth/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "senha123"
}
```

**Response 201 Created:**
```json
{
  "id": 1,
  "username": "newuser",
  "emailVerified": false
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "user",
  "password": "password"
}
```

**Response 200 OK:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Response 200 OK:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",  // Novo token
  "refreshToken": "eyJhbGciOiJIUzI1NiJ9..."  // Mesmo token
}
```

#### Verificar Email
```http
GET /auth/verify-email?token={TOKEN_DO_EMAIL}
```

**Response 200 OK:**
```json
{
  "message": "Email verificado com sucesso!",
  "verified": true
}
```

#### Solicitar Reset de Senha
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**Response 200 OK:**
```json
{
  "message": "Email de reset enviado!"
}
```

> 📧 Email será enviado para o Mailtrap

#### Resetar Senha
```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "TOKEN_DO_EMAIL",
  "newPassword": "novaSenha123"
}
```

**Response 200 OK:**
```json
{
  "message": "Senha alterada com sucesso!"
}
```

### Usuários (Protegido)

#### Obter Perfil do Usuário Autenticado
```http
GET /api/users/me
Authorization: Bearer {ACCESS_TOKEN}
```

**Response 200 OK:**
```json
{
  "username": "user",
  "authorities": [
    {
      "authority": "ROLE_USER"
    }
  ]
}
```

### Códigos de Status

| Código | Descrição |
|--------|-----------|
| 200 | Sucesso |
| 201 | Criado com sucesso |
| 400 | Requisição inválida |
| 401 | Não autenticado |
| 403 | Não autorizado (sem permissão) |
| 404 | Recurso não encontrado |
| 409 | Conflito (ex: usuário já existe) |
| 500 | Erro interno do servidor |

## 🧪 Testes

### Executar Testes

```bash
# Rodar todos os testes
./mvnw test

# Rodar testes com relatório de cobertura
./mvnw clean test jacoco:report
```

### Relatório de Cobertura

Após executar os testes com JaCoCo:

```bash
# Abrir relatório HTML
open target/site/jacoco/index.html
```

### Cobertura de Código

O projeto possui alta cobertura de testes unitários:

- ✅ `EmailService` - 100%
- ✅ `CustomUserDetailsService` - 100%
- ✅ `VerificationService` - 100%
- ✅ `AuthService` - 100%
- ✅ `UserService` - 100%

### Estrutura de Testes

```
src/test/java/
└── com/atwo/paganois/
    ├── services/
    │   ├── EmailServiceTest.java
    │   ├── CustomUserDetailsServiceTest.java
    │   ├── VerificationServiceTest.java
    │   ├── AuthServiceTest.java
    │   └── UserServiceTest.java
    └── controllers/
        └── (testes de integração futuros)
```

## 📁 Estrutura do Projeto

```
src/main/java/com/atwo/paganois/
├── config/                 # Configurações (Security, OpenAPI)
│   ├── OpenApiConfig.java
│   └── SecurityConfig.java
├── controllers/            # Controllers REST
│   ├── AuthController.java
│   └── UserController.java
├── dtos/                   # Data Transfer Objects
│   ├── LoginRequest.java
│   ├── LoginResponse.java
│   ├── RegisterRequest.java
│   ├── RegisterResponse.java
│   └── UserDTO.java
├── entities/               # Entidades JPA
│   ├── User.java
│   ├── Role.java
│   ├── VerificationToken.java
│   └── TokenType.java
├── exceptions/             # Exceções customizadas
│   ├── UserAlreadyExistsException.java
│   ├── AccountDisabledException.java
│   └── UserNotFoundException.java
├── repositories/           # Repositórios JPA
│   ├── UserRepository.java
│   ├── RoleRepository.java
│   └── VerificationTokenRepository.java
├── security/               # Componentes de segurança
│   ├── JwtAuthFilter.java
│   └── JwtUtil.java
├── services/               # Lógica de negócio
│   ├── AuthService.java
│   ├── UserService.java
│   ├── CustomUserDetailsService.java
│   ├── VerificationService.java
│   └── EmailService.java
└── DataLoader.java         # Carrega dados iniciais
```

## 🗺️ Roadmap

### Melhorias Planejadas

- [ ] **OAuth2/Social Login** (Google, GitHub)
- [ ] **Two-Factor Authentication (2FA)**
- [ ] **Rate Limiting** (proteção contra brute-force)
- [ ] **Docker e Docker Compose**
- [ ] **Testes de Integração** (`@SpringBootTest`, `@WebMvcTest`)
- [ ] **CI/CD** (GitHub Actions)
- [ ] **Migração para PostgreSQL** (produção)
- [ ] **Redis** para cache de tokens
- [ ] **Kubernetes** deployment config
- [ ] **Observabilidade** (Prometheus, Grafana)
- [ ] **API Versioning** (`/api/v1/...`)
- [ ] **CORS** configurável
- [ ] **Audit Log** (registro de ações)
- [ ] **Soft Delete** para usuários
- [ ] **Email Templates** com Thymeleaf

### Sugestões de Melhorias Técnicas

1. **Validação de Input**
   - Adicionar `@Valid` e validações mais robustas nos DTOs
   - Validação de força de senha

2. **Exception Handling**
   - `@ControllerAdvice` global para tratamento de exceções
   - Respostas de erro padronizadas

3. **Segurança**
   - HTTPS obrigatório em produção
   - CORS configurado adequadamente
   - Rate limiting por IP
   - Blacklist de tokens revogados

4. **Banco de Dados**
   - Migração para PostgreSQL/MySQL em produção
   - Flyway/Liquibase para migrations
   - Índices otimizados

5. **Observabilidade**
   - Spring Boot Actuator
   - Métricas customizadas
   - Health checks

6. **Performance**
   - Cache com Redis (tokens, usuários)
   - Connection pooling otimizado
   - Lazy loading configurado

## 🤝 Contribuindo

Contribuições são bem-vindas! Este projeto é para fins educacionais, mas melhorias são sempre apreciadas.

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request


