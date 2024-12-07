package git.io.jwt.security.component;

import com.szs.assignment.application.security.model.Token;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationProviderTest {

    private final JwtTokenService mockJwtTokenService = mock(JwtTokenService.class);

    private final JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(
            mockJwtTokenService
    );

    @Test
    void supportTrue() {
        boolean supports = jwtAuthenticationProvider.supports(Token.TokenAuthentication.class);
        Assertions.assertThat(supports).isTrue();
    }

    @Test
    void supportFalse() {
        boolean supports = jwtAuthenticationProvider.supports(String.class);
        Assertions.assertThat(supports).isFalse();
    }

    @Test
    void authenticate() {
        when(mockJwtTokenService.parserToken(any())).thenReturn(new Token.TokenPayload("test", List.of("user")));

        Token.TokenAuthentication tokenAuthentication = new Token.TokenAuthentication("test", "user");
        Assertions.assertThatCode(() -> {
            jwtAuthenticationProvider.authenticate(tokenAuthentication);
        }).doesNotThrowAnyException();
    }

}