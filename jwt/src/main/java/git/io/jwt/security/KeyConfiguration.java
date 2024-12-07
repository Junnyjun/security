package git.io.jwt.security;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class KeyConfiguration {

    @Bean
    public JwtKey jwtKey() {
        return new JwtKey(
                "szs-secret",
                "szs",
                Keys.hmacShaKeyFor("V1D9k3K3u5X3a9f0G1Q2m3L4n5O6p7Q8".getBytes(StandardCharsets.UTF_8)),
                1000
        );
    }

    @Bean("encryptionKey")
    public String encryptionKey() {
        return "1234567890123456";
    }

    public record JwtKey(
            String secret,
            String issuer,
            SecretKey key,
            int expiration
    ) {

    }
}
