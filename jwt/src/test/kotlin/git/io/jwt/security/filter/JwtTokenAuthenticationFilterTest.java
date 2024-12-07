package git.io.jwt.security.filter;

import com.szs.assignment.application.security.component.JwtTokenService;
import com.szs.assignment.application.security.model.Token;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtTokenAuthenticationFilterTest {
    private final JwtTokenService mockJwtTokenService = mock(JwtTokenService.class);
    private final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

    private final JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter = new JwtTokenAuthenticationFilter(
            new AntPathRequestMatcher("/api/**"),
            (request, response, exception) -> {
            },
            mockJwtTokenService
    );

    private final MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    private final MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();

    @Test
    void getFilterProcessesUrl() throws ServletException, IOException {
        jwtTokenAuthenticationFilter.setAuthenticationManager(authenticationManager);
        mockHttpServletRequest.addHeader("Authorization", "Bearer test");

        when(mockJwtTokenService.parserToken(any())).thenReturn(new Token.TokenPayload("test", List.of("test")));
        when(authenticationManager.authenticate(any())).thenReturn(new Token.TokenAuthentication("test", "test"));

        Authentication authentication = jwtTokenAuthenticationFilter.attemptAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse
        );

        assertNotNull(authentication);
    }

    @Test
    void successfulAuthentication() throws ServletException, IOException {
        jwtTokenAuthenticationFilter.setAuthenticationManager(authenticationManager);
        mockHttpServletRequest.addHeader("Authorization", "Bearer test");

        when(mockJwtTokenService.parserToken(any())).thenReturn(new Token.TokenPayload("test", List.of("test")));
        when(authenticationManager.authenticate(any())).thenReturn(new Token.TokenAuthentication("test", "test"));

        Authentication authentication = jwtTokenAuthenticationFilter.attemptAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse
        );

        jwtTokenAuthenticationFilter.successfulAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse,
                new MockFilterChain(),
                authentication
        );

        assertNotNull(authentication);
    }

    @Test
    void unsuccessfulAuthentication() throws ServletException, IOException {
        jwtTokenAuthenticationFilter.setAuthenticationManager(authenticationManager);
        mockHttpServletRequest.addHeader("Authorization", "Bearer test");

        when(mockJwtTokenService.parserToken(any())).thenReturn(new Token.TokenPayload("test", List.of("test")));
        when(authenticationManager.authenticate(any())).thenReturn(new Token.TokenAuthentication("test", "test"));

        Authentication authentication = jwtTokenAuthenticationFilter.attemptAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse
        );

        jwtTokenAuthenticationFilter.unsuccessfulAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse,
                new BadCredentialsException("Invalid token")
        );

        assertNotNull(authentication);
    }

    @Test
    void badExtract() throws ServletException, IOException {
        mockHttpServletRequest.addHeader("Authorization", "bad test");

        Assertions.assertThrows(BadCredentialsException.class, () -> {
            jwtTokenAuthenticationFilter.attemptAuthentication(
                    mockHttpServletRequest,
                    mockHttpServletResponse
            );
        });
    }

}