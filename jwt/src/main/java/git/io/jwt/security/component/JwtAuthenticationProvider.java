package git.io.jwt.security.component;

import com.szs.assignment.application.security.model.Token;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtTokenService tokenService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authenticate((Token.TokenAuthentication) authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (Token.TokenAuthentication.class.isAssignableFrom(authentication));
    }

    private Authentication authenticate(Token.TokenAuthentication authentication) throws AuthenticationException {
        String jwtToken = authentication.getCredentials();
        Token.TokenPayload response = tokenService.parserToken(jwtToken);

        return new Token.TokenAuthentication(response.username(), response.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .toList());
    }

}