package git.io.jwt.security.model;

public class Login {
    public record LoginRequest(
            String userId,
            String password
    ) {
    }

    public record LoginResponse(
            String accessToken
    ) {
    }
}
