package git.io.jwt.security.model;

import com.szs.assignment.application.security.component.SkipRequestMatcher;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SkipRequestMatcherTest {
    private final SkipRequestMatcher matcher = new SkipRequestMatcher(
            List.of("/szs/auth/login"),
            "/szs/**"
    );

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    @Test
    void validFail() {
        assertThrows(IllegalArgumentException.class, () -> {
            new SkipRequestMatcher(null, "/szs/**");
        });
    }

    @Test
    void matches() {
        request.setRequestURI("/szs/auth/login");
        request.setServletPath("/szs/auth/login");


        assertFalse(matcher.matches(request));
    }

    @Test
    void matchesFalse() {
        request.setRequestURI("/szs/auth/logout");

        assertFalse(matcher.matches(request));
    }

    @Test
    void matcherTest() {
        assertNotNull(matcher.matcher(request));
    }

}