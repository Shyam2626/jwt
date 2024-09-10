package com.shyam.jwt.config
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.*


@Service
class JwtService {

    private val SECRET_KEY : String = "AE3CCA5BA326C4AC5C4DF37B5C75AIAHD7AYDQH38HQ98D98CH98AH98"

    fun extractUserName(token : String ) : String{
        return extractClaim(token, Claims:: getSubject)
    }

    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T {
        val claims: Claims = extractAllClaims(token)
        return claimsResolver(claims)
    }

    fun extractAllClaims(token : String) : Claims{
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(token)
            .body
    }


    fun getSignInKey(): Key {
        val keyBytes: ByteArray = Decoders.BASE64.decode(SECRET_KEY) // SECRET_KEY should be a Base64-encoded string
        return Keys.hmacShaKeyFor(keyBytes)
    }


    fun generateToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String {
        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 24))
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact()
    }

    fun generateToken(userDetails: UserDetails): String {
        return generateToken(mapOf(), userDetails)
    }

    fun isTokenValid(token : String, userDetails: UserDetails) : Boolean {
        val username = extractUserName(token)
        return (username.equals(userDetails.username)) && !isTokenExpired(token);
    }

    private fun isTokenExpired(token: String): Boolean {
            return extractExpiration(token).before(Date())
    }

    private fun extractExpiration(token: String): Date {
        return extractClaim(token, Claims :: getExpiration)
    }


}