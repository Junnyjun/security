package git.io.jwt.security.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;

class JwtTokenIssueSuccessHandlerTest {
    private final JwtTokenService mockJwtTokenService = mock(JwtTokenService.class);


    private final JwtTokenIssueSuccessHandler handler = new JwtTokenIssueSuccessHandler(
            new ObjectMapper(),
            mockJwtTokenService
    );

    private final MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    private final MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    private final UsernamePasswordAuthenticationToken jwtAuthenticationToken = new UsernamePasswordAuthenticationToken("test", "user");


    @Test
    void onAuthenticationSuccess() {
        assertDoesNotThrow(() -> {
            handler.onAuthenticationSuccess(
                    mockHttpServletRequest,
                    mockHttpServletResponse,
                    jwtAuthenticationToken
            );

            Assertions.assertEquals(200, mockHttpServletResponse.getStatus());
        });
    }


    @Test
    void onAuthenticationSuccessWithJwtToken() {
        MockHttpSession mockHttpSession = new MockHttpSession();

        assertDoesNotThrow(() -> {
            mockHttpServletRequest.setSession(
                    mockHttpSession
            );

            handler.onAuthenticationSuccess(
                    mockHttpServletRequest,
                    mockHttpServletResponse,
                    jwtAuthenticationToken
            );

            Assertions.assertEquals(200, mockHttpServletResponse.getStatus());
        });
    }
}