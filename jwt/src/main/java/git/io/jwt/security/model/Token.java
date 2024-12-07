package git.io.jwt.security.model;

import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class Token {
    public record TokenPayload(String username, List<String> roles) {
    }

    @EqualsAndHashCode(of = {"jwtToken", "username"}, callSuper = true)
    public static class TokenAuthentication extends AbstractAuthenticationToken {
        private final String jwtToken;
        private final String username;

        public TokenAuthentication(String jwtToken, String username) {
            super(null);
            this.setAuthenticated(false);
            this.jwtToken = jwtToken;
            this.username = username;
        }

        public TokenAuthentication(String username, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.eraseCredentials();
            super.setAuthenticated(true);
            this.username = username;
            this.jwtToken = null;
        }

        @Override
        public String getCredentials() {
            return this.jwtToken;
        }

        @Override
        public String getPrincipal() {
            return username;
        }

    }
}
