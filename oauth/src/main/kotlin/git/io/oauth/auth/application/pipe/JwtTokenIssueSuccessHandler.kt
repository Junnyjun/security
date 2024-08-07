package git.io.jwt.auth.application.pipe

import com.fasterxml.jackson.databind.ObjectMapper
import git.io.jwt.auth.domain.TokenValue
import git.io.jwt.auth.service.TokenService
import io.jsonwebtoken.io.IOException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.web.WebAttributes
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.util.Objects.isNull


@Component
class JwtTokenIssueSuccessHandler(
    private val objectMapper: ObjectMapper,
    private val tokenService: TokenService
) : AuthenticationSuccessHandler {


    @Throws(IOException::class)
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val username = authentication.principal.toString()
        val authorities: List<SimpleGrantedAuthority> = authentication.authorities
            .map { SimpleGrantedAuthority(it.authority) }
            .toList()

        val tokenResponse = TokenValue(tokenService.createToken(username, authorities))

        response.status = HttpStatus.OK.value()
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(response.writer, tokenResponse)

        val session = request.getSession(false)
        if (!isNull(session)) {
            session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
        }
    }

}