package com.atwo.paganois.security;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.atwo.paganois.services.RateLimitService;
import com.atwo.paganois.services.RateLimitService.RateLimitResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro que aplica rate limiting antes de qualquer processamento.
 * 
 * Executa ANTES de outros filtros. Isso significa que mesmo requests com tokens inválidos são
 * contados no rate limit, protegendo contra ataques de força bruta.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimitService rateLimitService, ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String ip = getClientIP(request);
        String path = request.getRequestURI();
        String method = request.getMethod();

        // Só aplica rate limit para POST (mutações)
        if (!"POST".equalsIgnoreCase(method)) {
            filterChain.doFilter(request, response);
            return;
        }

        RateLimitResult result = getRateLimitResult(path, ip);

        if (result == null) {
            // Endpoint não tem rate limit específico
            filterChain.doFilter(request, response);
            return;
        }

        // Adiciona headers informativos (útil para debugging e clientes)
        response.setHeader("X-RateLimit-Remaining", String.valueOf(result.remainingTokens()));

        if (!result.allowed()) {
            response.setHeader("X-RateLimit-Retry-After",
                    String.valueOf(result.retryAfterSeconds()));
            response.setHeader("Retry-After", String.valueOf(result.retryAfterSeconds()));

            sendRateLimitResponse(request, response, result.retryAfterSeconds());
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Determina qual rate limit aplicar baseado no path
     */
    private RateLimitResult getRateLimitResult(String path, String ip) {
        if (path.equals("/auth/login")) {
            return rateLimitService.tryConsumeLogin(ip);
        }
        if (path.equals("/auth/register")) {
            return rateLimitService.tryConsumeRegister(ip);
        }
        if (path.equals("/auth/forgot-password")) {
            return rateLimitService.tryConsumeForgotPassword(ip);
        }
        if (path.equals("/auth/resend-verification")) {
            return rateLimitService.tryConsumeResendVerification(ip);
        }

        // Para outros endpoints autenticados, aplica limite geral
        if (path.startsWith("/api/")) {
            return rateLimitService.tryConsumeGeneral(ip);
        }

        return null; // Sem rate limit
    }

    /**
     * Extrai IP real do cliente, considerando proxies e load balancers
     */
    private String getClientIP(HttpServletRequest request) {
        // Headers comuns usados por proxies reversos
        String[] headerNames = {"X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP",
                "WL-Proxy-Client-IP", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP"};

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // X-Forwarded-For pode ter múltiplos IPs: "client, proxy1, proxy2"
                // Pegamos o primeiro (cliente original)
                return ip.split(",")[0].trim();
            }
        }

        // Fallback: IP direto da conexão
        return request.getRemoteAddr();
    }

    /**
     * Envia resposta 429 Too Many Requests
     */
    private void sendRateLimitResponse(HttpServletRequest request, HttpServletResponse response,
            long retryAfterSeconds) throws IOException {

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorBody = Map.of("timestamp", Instant.now().toString(), "status", 429,
                "error", "Too Many Requests", "message",
                String.format("Muitas requisições. Tente novamente em %d segundos.",
                        retryAfterSeconds),
                "path", request.getRequestURI(), "retryAfterSeconds", retryAfterSeconds);

        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }
}
