package com.shyam.jwt.auth

import AuthenticationRequest
import AuthenticationResponse
import RegisterRequest
import com.shyam.jwt.config.JwtService
import com.shyam.jwt.user.User
import com.shyam.jwt.user.UserRepository
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthenticationService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val authenticationManager: AuthenticationManager
) {

    fun register(request: RegisterRequest): AuthenticationResponse {

        val user = User(
            firstName = request.firstName,
            lastName = request.lastName,
            email = request.email,
            password = passwordEncoder.encode(request.password),
            role = request.role
        )

        userRepository.save(user)

        var jwtToken = jwtService.generateToken(user)
        return AuthenticationResponse(jwtToken)
    }

    fun authenticate(request: AuthenticationRequest): AuthenticationResponse {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                request.email,
                request.password
            )
        )
        var user = userRepository.findByEmail(request.email).orElseThrow()
        var jwtToken = jwtService.generateToken(user)
        return AuthenticationResponse(jwtToken)
    }
}
