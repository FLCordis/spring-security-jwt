package flcordis.spring_security_jwt.security;

import java.util.List;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTCreator {
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String ROLES_AUTHORITIES = "authorities";

    // Método para criar o token
    public static String create(String prefix, String key, JWTObject jwtObject) {
        String token = JWT.create()
                .withSubject(jwtObject.getSubject())
                .withIssuedAt(jwtObject.getIssuedAt())
                .withExpiresAt(jwtObject.getExpiration())
                .withClaim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles()))
                .sign(Algorithm.HMAC512(key));  // Use HMAC512 (equivalente ao HS512)
        return prefix + " " + token;
    }

    // Método para validar e criar o objeto JWTObject a partir do token
    public static JWTObject create(String token, String prefix, String key)
            throws JWTDecodeException, SignatureVerificationException {
        JWTObject object = new JWTObject();
        token = token.replace(prefix, "");
        
        // Verifica o token com a chave secreta
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(key))
                .build()
                .verify(token);
        
        object.setSubject(decodedJWT.getSubject());
        object.setExpiration(decodedJWT.getExpiresAt());
        object.setIssuedAt(decodedJWT.getIssuedAt());
        object.setRoles(decodedJWT.getClaim(ROLES_AUTHORITIES).asList(String.class));
        
        return object;
    }

    // Método para formatar os papéis
    private static List<String> checkRoles(List<String> roles) {
        return roles.stream()
                .map(s -> "ROLE_".concat(s.replaceAll("ROLE_", "")))
                .collect(Collectors.toList());
    }
}