package git.io.jwt.security.component;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

import static java.util.stream.Collectors.toList;


public class SkipRequestMatcher implements RequestMatcher {
    private final OrRequestMatcher matchers;
    private final RequestMatcher processingMatcher;

    public SkipRequestMatcher(List<String> pathsToSkip, String processingPath) {
        if (pathsToSkip == null) {
            throw new IllegalArgumentException("pathsToSkip cannot be null");
        }
        this.matchers = new OrRequestMatcher(
                pathsToSkip.stream()
                        .map(AntPathRequestMatcher::new)
                        .collect(toList())
        );
        this.processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (matchers.matches(request)) {
            return false;
        }
        return processingMatcher.matches(request);
    }

    @Override
    public MatchResult matcher(HttpServletRequest request) {
        return RequestMatcher.super.matcher(request);
    }

}