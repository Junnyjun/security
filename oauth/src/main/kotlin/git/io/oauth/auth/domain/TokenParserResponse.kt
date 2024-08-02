package git.io.jwt.auth.domain


open class TokenParserResponse(val username: String, val roles: List<Any>)