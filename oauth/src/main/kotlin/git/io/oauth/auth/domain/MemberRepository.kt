package git.io.jwt.auth.domain

import git.io.jwt.auth.domain.Member
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface MemberRepository : JpaRepository<Member, Long> {
    fun findByUsername(username: String): Member?
}