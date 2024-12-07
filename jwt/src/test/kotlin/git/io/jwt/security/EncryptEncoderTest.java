package git.io.jwt.security;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class EncryptEncoderTest {
    private final EncryptEncoder encryptor = new EncryptEncoder(
            new KeyConfiguration().encryptionKey()
    );

    @Test
    void encryptTest() {
        String password = "password";
        String encrypted = "mcM3yWWT+8sre6MjlFUpww==";

        String encodedPassword = encryptor.encrypt(password);
        Assertions.assertThat(encodedPassword).isEqualTo(encrypted);
    }

    @Test
    void decryptTest() {
        String password = "password";
        String encrypted = "mcM3yWWT+8sre6MjlFUpww==";
        String encodedPassword = encryptor.decrypt(encrypted);

        Assertions.assertThat(encodedPassword).isEqualTo(password);
    }

}