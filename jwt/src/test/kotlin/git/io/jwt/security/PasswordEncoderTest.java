package git.io.jwt.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordEncoderTest {
    BCryptPasswordEncoder passwordEncoder = new PasswordEncoder().bCryptPasswordEncoder();

    @Test
    void bCryptPasswordEncoder() {
        final var encrypted = "$2a$10$fodTlJxblvHH5E3brchfYumfz2TKAM.s47xKw6uVB1OWmPAW2yLba";
        final var target = "sample";
        final var encode = passwordEncoder.matches(target, encrypted);

        assertThat(encode).isTrue();
    }

}