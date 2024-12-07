package git.io.jwt.security.component;

import com.szs.assignment.application.security.KeyConfiguration;
import com.szs.assignment.application.security.model.Token;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtTokenServiceTest {
    private final JwtTokenService jwtTokenService = new JwtTokenService(
            new KeyConfiguration().jwtKey()
    );

    @Test
    void createToken() {
        String token = jwtTokenService.createToken("test",
                List.of(new SimpleGrantedAuthority("user")));
        assertNotNull(token);
    }

    @Test
    void parserToken() {
        String token = jwtTokenService.createToken("test", List.of(new SimpleGrantedAuthority("user")));
        Token.TokenPayload tokenPayload = jwtTokenService.parserToken(token);
        assertEquals("test", tokenPayload.username());
        assertEquals(1, tokenPayload.roles().size());
    }

    @Test
    void parserTokenFail() {
        final String token = "bad_token";
        assertThrows(Exception.class, () -> jwtTokenService.parserToken(token));
    }
}