package flcordis.spring_security_jwt.security;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;  // Certifique-se de importar isso
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Obtem o token da request com AUTHORIZATION
        String token = request.getHeader(JWTCreator.HEADER_AUTHORIZATION);
        
        try {
            if (token != null && !token.isEmpty()) {
                // Remove o prefixo do token (caso exista)
                token = token.replace(SecurityConfig.PREFIX, "").trim();

                // Valida o token e extrai o objeto JWT
                JWTObject tokenObject = JWTCreator.create(token, SecurityConfig.PREFIX, SecurityConfig.KEY);

                // Obtém as authorities a partir dos papéis do token
                List<SimpleGrantedAuthority> authorities = authorities(tokenObject.getRoles());

                // Cria o AuthenticationToken com o subject do token e as authorities
                UsernamePasswordAuthenticationToken userToken =
                        new UsernamePasswordAuthenticationToken(
                                tokenObject.getSubject(),
                                null,
                                authorities);

                // Define o contexto de segurança
                SecurityContextHolder.getContext().setAuthentication(userToken);

            } else {
                // Se não houver token, limpa o contexto de segurança
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        } catch (JWTDecodeException | SignatureVerificationException e) {
            // Exceções relacionadas a problemas com o token
            e.printStackTrace();
            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 Forbidden
            return;
        }
    }

    // Converte os papéis (roles) em SimpleGrantedAuthority
    private List<SimpleGrantedAuthority> authorities(List<String> roles) {
        return roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}