package com.tpam.service.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JsonWebTokenUtility {

    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private final String signatureKey;

    public JsonWebTokenUtility(@Value("${security.jwt.signature-key}") final String signatureKey) {
        this.signatureKey = signatureKey;
    }

    public String parseToken(final HttpServletRequest req) {
        final String bearerToken = req.getHeader(AUTHORIZATION_HEADER);
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.replace(TOKEN_PREFIX, "");
        }
        return null;
    }

    public Authentication authenticate(final String token) {
        Authentication auth = null;
        final Claims claims = parseClaims(token);
        final String username = claims.getSubject();
        if (username != null) {
            final List<String> authorities = (List<String>) claims.get("authorities");
            auth = new UsernamePasswordAuthenticationToken(
                username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        }
        return auth;
    }

    private Claims parseClaims(final String token) {
        return Jwts.parser().setSigningKey(signatureKey.getBytes()).parseClaimsJws(token).getBody();
    }
}
