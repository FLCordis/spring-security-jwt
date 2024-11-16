package flcordis.spring_security_jwt.docs;

import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("API com JWT Security e Database H2")
                .version("1.0")
                .description("Documentação da API de Teste usando Swagger e OpenAPI 3"));
    }
}
