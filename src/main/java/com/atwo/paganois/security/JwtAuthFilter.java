package com.atwo.paganois.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.atwo.paganois.services.CustomUserDetailsService;
import com.atwo.paganois.services.TokenRevocationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private TokenRevocationService tokenRevocationService;

    private static final List<String> PUBLIC_URLS =
            Arrays.asList("/auth/", "/h2-console/", "/v3/api-docs/", "/api-docs/", "/swagger-ui/",
                    "/swagger-ui.html", "/swagger-resources/", "/webjars/");

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        boolean isPublic = PUBLIC_URLS.stream().anyMatch(path::startsWith);

        if (isPublic) {
            logger.debug("Skipping JWT filter for public URL: {}", path);
        }

        return isPublic;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                if (jwtUtil.validateToken(token)) {
                    if (tokenRevocationService.isRevoked(token)) {
                        logger.warn("Access token revogado individualmente");
                        filterChain.doFilter(request, response);
                        return;
                    }

                    if (!jwtUtil.validateTokenWithVersion(token)) {
                        logger.warn("Access token com versão desatualizada");
                        filterChain.doFilter(request, response);
                        return;
                    }
                    String username = jwtUtil.extractUsername(token);

                    if (username != null
                            && SecurityContextHolder.getContext().getAuthentication() == null) {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null,
                                        userDetails.getAuthorities());

                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
