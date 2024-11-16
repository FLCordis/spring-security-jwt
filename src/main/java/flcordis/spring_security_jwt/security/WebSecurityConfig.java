package flcordis.spring_security_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.servlet.Filter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Usando BCryptPasswordEncoder
    }

    @SuppressWarnings("removal")
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**", "/swagger-ui/**", "/v3/api-docs/**")  // Ignora CSRF para URLs públicas
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/h2-console/**", "/swagger-ui/**", "/v3/api-docs/**", "/public/**")
                .permitAll()  // Permite o acesso sem autenticação
                .anyRequest().authenticated()  // Requer autenticação para outras requisições
            )
            .headers(headers -> headers
                .frameOptions().sameOrigin()  // Permite o uso do H2 Console
            )
            .addFilterBefore(jwtFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Filtro JWT que você já tem implementado
    @Bean
    public Filter jwtFilter() {
        return new JWTFilter();  // O seu filtro JWT customizado
    }
}