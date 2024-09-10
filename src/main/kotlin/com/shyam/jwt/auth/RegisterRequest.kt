import com.shyam.jwt.user.Role

data class RegisterRequest(
    val firstName: String,
    val lastName: String,
    val email: String,
    val password: String,
    val role: Role = Role.USER
)
