package git.io.jwt.security.component;

import com.szs.assignment.application.security.KeyConfiguration.JwtKey;
import com.szs.assignment.application.security.model.Token;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static com.szs.assignment.application.exception.SecurityException.JwtExpiredTokenException;

@Component
public class JwtTokenService {
    private static final String AUTHORITIES_KEY = "roles";
    private final JwtKey jwtKey;

    public JwtTokenService(JwtKey key) {
        this.jwtKey = key;
    }

    public String createToken(String username, Collection<GrantedAuthority> authorities) {
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiredAt = issuedAt.plusMinutes(jwtKey.expiration());

        return Jwts.builder()
                .addClaims(createClaims(username, authorities))
                .setIssuer(jwtKey.issuer())
                .setIssuedAt(toDate(issuedAt))
                .setExpiration(toDate(expiredAt))
                .signWith(jwtKey.key())
                .compact();
    }

    public Token.TokenPayload parserToken(String token) throws BadCredentialsException, JwtExpiredTokenException {
        try {
            Claims body = Jwts.parserBuilder()
                    .setSigningKey(jwtKey.key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return new Token.TokenPayload(
                    body.getSubject(),
                    body.get("roles", List.class)
            );
        } catch (SignatureException | UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid JWT token", ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException("JWT Token expired", expiredEx);
        }
    }

    private Claims createClaims(String username, Collection<GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTHORITIES_KEY, authorities.stream().map(Object::toString).toList());
        return claims;
    }

    private Date toDate(LocalDateTime dateTime) {
        return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
