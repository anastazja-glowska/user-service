package com.appsdeveloperblog.tutorials.junit.security;

import com.appsdeveloperblog.tutorials.junit.io.UsersRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    UsersRepository userRepository;

    public AuthorizationFilter(AuthenticationManager authManager,
                               UsersRepository userRepository) {
        super(authManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        String header = req.getHeader(SecurityConstants.HEADER_STRING);

        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);

        if (token == null) return null;

        token = token.replace(SecurityConstants.TOKEN_PREFIX, "").trim();
        byte[] secretKeyBytes = SecurityConstants.TOKEN_SECRET.getBytes();
        SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);

        try {

            JwtParser parser = Jwts.parser()
                    .verifyWith(secretKey)
                    .build();
            Claims claims = parser.parseSignedClaims(token).getPayload();
            String user = (String) claims.get("sub");

            if (user != null) {
                String role = (String) claims.get("role");

                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                if (role != null) {
                    authorities.add(new SimpleGrantedAuthority(role));
                    System.out.println("HERE IS ROLE " + role);
                    System.out.println("Authorities: " + authorities);

                }


                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }

        } catch(Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

}