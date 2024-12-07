package git.io.jwt.security.component;

import com.szs.assignment.user.model.UserInfo;
import com.szs.assignment.user.service.FindUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class LoginUserDetailService implements UserDetailsService {
    private final FindUser findUser;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo user = findUser.findUser(username);

        return new User(
                user.userId(),
                user.password(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}
