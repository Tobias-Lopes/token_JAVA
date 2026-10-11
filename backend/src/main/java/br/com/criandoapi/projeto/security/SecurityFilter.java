package br.com.criandoapi.projeto.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // Verifica se o cabeçalho não é nulo E se contém a palavra Bearer seguida do token
        if (authHeader != null && authHeader.startsWith("Bearer ") && authHeader.length() > 7) {
            try {
                Authentication auth = TokenUtil.validate(request);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                // Se o token for expirado ou malformado, o servidor limpa o erro e devolve 401
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}