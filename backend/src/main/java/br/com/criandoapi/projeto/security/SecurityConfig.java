package br.com.criandoapi.projeto.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSec) throws Exception {
        httpSec
                // 1. Desabilita o CSRF usando a nova sintaxe lambda
                .csrf(AbstractHttpConfigurer::disable)
                // 2. Configura o CORS
                .cors(Customizer.withDefaults())
                // 3. Configura a autorização das rotas (substituindo antMatchers por requestMatchers)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/usuarios/login").permitAll()
                        .anyRequest().authenticated()
                )
                // 4. Adiciona o seu filtro personalizado ANTES do filtro de autenticação padrão
                .addFilterBefore(new SecurityFilter(), UsernamePasswordAuthenticationFilter.class);

        // 5. Constrói e retorna a cadeia de filtros
        return httpSec.build();
    }
}