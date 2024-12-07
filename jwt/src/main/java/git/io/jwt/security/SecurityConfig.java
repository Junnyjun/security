package git.io.jwt.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.szs.assignment.application.security.component.JwtAuthenticationProvider;
import com.szs.assignment.application.security.component.JwtTokenProvider;
import com.szs.assignment.application.security.component.JwtTokenService;
import com.szs.assignment.application.security.component.SkipRequestMatcher;
import com.szs.assignment.application.security.filter.JwtTokenAuthenticationFilter;
import com.szs.assignment.application.security.filter.JwtTokenIssueFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toStaticResources;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private static final String LOGIN_URL = "/szs/login";
    private static final String SIGNUP_URL = "/szs/signup";
    private static final String ERROR = "/error";
    private static final String ROOT_URL = "/szs/**";

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final JwtTokenProvider jwtTokenIssueProvider;

    private final JwtTokenService jwtTokenService;
    private final ObjectMapper objectMapper;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        //disableUnused
        http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable);

        // add Filter
        http.addFilterBefore(jwtTokenIssueFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtTokenAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);

        // add authentication
        http.authorizeHttpRequests(this::authorizeHttpRequests);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        var authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(jwtAuthenticationProvider);
        authenticationManagerBuilder.authenticationProvider(jwtTokenIssueProvider);
        return authenticationManagerBuilder.build();
    }

    private void authorizeHttpRequests(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry configurer) {
        configurer
                .requestMatchers(toStaticResources().atCommonLocations()).permitAll()
                .requestMatchers(ERROR).permitAll()
                .requestMatchers(LOGIN_URL, SIGNUP_URL).permitAll()
                .requestMatchers("/szs/**").hasAnyRole("USER")
                .requestMatchers("/3o3/**").permitAll();
    }

    private JwtTokenIssueFilter jwtTokenIssueFilter(AuthenticationManager authenticationManager) {
        final var filter = new JwtTokenIssueFilter("/szs/login", objectMapper, successHandler, failureHandler);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    private JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        final var matcher = new SkipRequestMatcher(List.of(
                ERROR,
                LOGIN_URL,
                SIGNUP_URL
        ), ROOT_URL);
        final var filter = new JwtTokenAuthenticationFilter(matcher, failureHandler, jwtTokenService);
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }


}
