package git.io.jwt.security.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.szs.assignment.application.exception.SecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

public class JwtAuthenticationFailureHandlerTest {
    private final JwtAuthenticationFailureHandler handler = new JwtAuthenticationFailureHandler(
            new ObjectMapper()
    );

    private final MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    private final MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();

    @Test
    void jwtTokenExpired() throws IOException {
        Assertions.assertDoesNotThrow(() -> {
            handler.onAuthenticationFailure(
                    mockHttpServletRequest,
                    mockHttpServletResponse,
                    new SecurityException.JwtExpiredTokenException("Test", new Throwable())
            );

            Assertions.assertEquals(401, mockHttpServletResponse.getStatus());
        });

    }
}