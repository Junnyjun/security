package git.io.jwt.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.szs.assignment.application.exception.SecurityException;
import com.szs.assignment.application.security.model.Token;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtTokenIssueFilterTest {
    private final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

    private final JwtTokenIssueFilter jwtTokenIssueFilter = new JwtTokenIssueFilter(
            "/szs/login",
            new ObjectMapper(),
            (request, response, authentication) -> {
            },
            (request, response, exception) -> {
            }
    );

    private final MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    private final MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();

    @Test
    void attemptAuthentication() {
        jwtTokenIssueFilter.setAuthenticationManager(authenticationManager);
        mockHttpServletRequest.setRequestURI("/szs/login");
        mockHttpServletRequest.setContent("""
                {
                    "userId": "test",
                    "password": "test"
                }
                
                """.getBytes()
        );
        mockHttpServletRequest.setMethod("POST");

        when(authenticationManager.authenticate(any())).thenReturn(new Token.TokenAuthentication("test", "test"));

        assertDoesNotThrow(() -> {
            jwtTokenIssueFilter.attemptAuthentication(
                    mockHttpServletRequest,
                    mockHttpServletResponse
            );
        });
    }

    @Test
    void attemptMethodFail() {
        mockHttpServletRequest.setRequestURI("/szs/login");
        mockHttpServletRequest.setMethod("GET");

        assertThrows(SecurityException.AuthMethodNotSupportedException.class, () -> {
            jwtTokenIssueFilter.attemptAuthentication(
                    mockHttpServletRequest,
                    mockHttpServletResponse
            );
        });
    }
}