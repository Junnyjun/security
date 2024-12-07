package git.io.jwt.security.component;

import com.szs.assignment.user.service.FindUser;
import org.junit.jupiter.api.Test;

import static com.szs.assignment.user.UserTestFixture.USER;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LoginUserDetailServiceTest {
    private final FindUser findUser = mock(FindUser.class);

    private final LoginUserDetailService loginUserDetailService = new LoginUserDetailService(
            findUser
    );

    @Test
    void loadUserByUsername() {
        when(findUser.findUser(any())).thenReturn(USER);

        assertDoesNotThrow(() -> {
            loginUserDetailService.loadUserByUsername("username");
        });
    }

}