package com.jwt.security.security.utils;

import com.jwt.security.security.constant.SecurityConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenUtils {

    private static byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SecurityConstant.JWT_SECRET_KEY);

    private static SecretKey secretKey = Keys.hmacShaKeyFor(apiKeySecretBytes);

    public static String createToken(String username, List<String> roles, boolean isRemember) {
        long expiration = isRemember ? SecurityConstant.EXPIRATION_REMEMBER : SecurityConstant.EXPIRATION;

        String tokenPrefix = Jwts.builder()
                .setHeaderParam("typ", SecurityConstant.TOKEN_TYPE)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .claim(SecurityConstant.ROLE_CLAIMS, String.join(",", roles))
                .setIssuer("ZiFeiYu")
                .setIssuedAt(new Date())
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
        return SecurityConstant.TOKEN_PRIFIX + tokenPrefix;
    }

    private boolean isTokenExpired(String token) {
        Date expireDate = getTokenBody(token).getExpiration();
        return expireDate.before(new Date());
    }

    public static String getUsernameByToken(String token) {
        return getTokenBody(token).getSubject();
    }

    public static List<SimpleGrantedAuthority> getUserRolesByToken(String token) {
        String role = (String) getTokenBody(token).get(SecurityConstant.ROLE_CLAIMS);
        return Arrays.stream(role.split(",")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    private static Claims getTokenBody(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

}
