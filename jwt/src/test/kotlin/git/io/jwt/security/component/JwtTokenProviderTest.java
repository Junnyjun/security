package git.io.jwt.security.component;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtTokenProviderTest {
    private final PasswordEncoder mockPasswordEncoder = mock(BCryptPasswordEncoder.class);


    private final JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(
            mockPasswordEncoder,
            username -> new User("username", "password", List.of(
                    () -> "ROLE_USER"
            ))
    );

    @Test
    void supportTrue() {
        assertTrue(jwtTokenProvider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void supportFalse() {
        assertFalse(jwtTokenProvider.supports(String.class));
    }

    @Test
    void authenticate() {
        when(mockPasswordEncoder.matches("password", "password")).thenReturn(true);

        var username = "username";
        var password = "password";
        var authenticate = jwtTokenProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        assertNotNull(authenticate);
    }

    @Test
    void authenticateFail() {
        when(mockPasswordEncoder.matches("password", "password")).thenReturn(false);

        var username = "username";
        var password = "password";
        assertThrows(Exception.class, () -> jwtTokenProvider.authenticate(new UsernamePasswordAuthenticationToken(username, password)));
    }

}