package git.io.jwt.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.szs.assignment.application.exception.SecurityException.AuthMethodNotSupportedException;
import com.szs.assignment.application.security.model.Login;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class JwtTokenIssueFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper;

    public JwtTokenIssueFilter(String defaultFilterProcessesUrl, ObjectMapper objectMapper, AuthenticationSuccessHandler authenticationSuccessHandler, AuthenticationFailureHandler authenticationFailureHandler) {
        super(defaultFilterProcessesUrl);
        this.objectMapper = objectMapper;
        this.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        this.setAuthenticationFailureHandler(authenticationFailureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        if (!isPostMethod(request)) {
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }

        var loginRequest = objectMapper.readValue(request.getReader(), Login.LoginRequest.class);
        var token = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.userId(), loginRequest.password());

        return this.getAuthenticationManager().authenticate(token);
    }

    private boolean isPostMethod(HttpServletRequest request) {
        return HttpMethod.POST.name().equals(request.getMethod());
    }
}