package git.io.jwt.security.filter;

import com.szs.assignment.application.security.component.JwtTokenService;
import com.szs.assignment.application.security.model.Token;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

import static java.util.Objects.isNull;

public class JwtTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final JwtTokenService tokenService;

    public JwtTokenAuthenticationFilter(RequestMatcher matcher, AuthenticationFailureHandler failureHandler, JwtTokenService tokenService) {
        super(matcher);
        this.tokenService = tokenService;
        this.setAuthenticationFailureHandler(failureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String jwtToken = extractToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        Token.TokenPayload tokenParserResponse = tokenService.parserToken(jwtToken);
        return getAuthenticationManager().authenticate(new Token.TokenAuthentication(jwtToken, tokenParserResponse.username()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException authenticationException) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        getFailureHandler().onAuthenticationFailure(request, response, authenticationException);
    }

    private String extractToken(String tokenPayload) {
        if (isNull(tokenPayload) || !tokenPayload.startsWith("Bearer ")) {
            throw new BadCredentialsException("Invalid token");
        }
        return tokenPayload.replace("Bearer ", "");
    }
}