package com.tpam.service.gateway.web.filter;

import com.tpam.service.gateway.security.JsonWebTokenUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenAuthenticationFilter.class);

    private final JsonWebTokenUtility jsonWebTokenUtility;

    public JwtTokenAuthenticationFilter(final JsonWebTokenUtility jsonWebTokenUtility) {
        this.jsonWebTokenUtility = jsonWebTokenUtility;
    }

    /**
     * 1. Get token. Tokens are supposed to be passed in the authentication header.
     * 2. If there is no token provided and hence the user won't be authenticated.
     * It's Ok. Maybe the user accessing a public path or asking for a token.
     * All secured paths that needs a token are already defined and secured in config class and If user tried to access without access token, then he won't be authenticated and an exception will be thrown.
     * 3. Validate the token
     * 5. Create auth object
     * 6. Authenticate the user
     *
     * @param request
     * @param response
     * @param chain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
        throws ServletException, IOException {

        final String token = jsonWebTokenUtility.parseToken(request);
        if (token != null) {
            try {
                final Authentication authentication = jsonWebTokenUtility.authenticate(token);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            catch (final Exception e) {
                logger.warn("Token validation failed with reason: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }
}