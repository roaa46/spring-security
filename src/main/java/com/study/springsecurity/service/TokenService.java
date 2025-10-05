package com.study.springsecurity.service;

import com.study.springsecurity.entity.Token;
import com.study.springsecurity.entity.User;
import com.study.springsecurity.enums.TokenType;
import com.study.springsecurity.repository.TokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final TokenRepository tokenRepository;
    @Value("${expiration}")
    private Long tokenExpiration;
    @Value("${refresh-token-expiration}")
    private Long refreshTokenExpiration;

    public void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokens(user.getId());
        if (validUserTokens.isEmpty())
            return;

        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });

        tokenRepository.saveAll(validUserTokens);
    }

    public void saveUserToken(User savedUser, String refreshToken) {
        Token token = Token.builder()
                .user(savedUser)
                .token(refreshToken)
                .tokenType(TokenType.BEARER)
                .isExpired(false)
                .isRevoked(false)
                .build();
        tokenRepository.save(token);
    }

    public void addTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        if (response == null)
            return;
        Cookie accessCookie = new Cookie("access_token", accessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false); // change to true in production
        accessCookie.setPath("/");
        accessCookie.setMaxAge((int) (tokenExpiration / 1000));

        Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false); //change to true in production
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge((int) (refreshTokenExpiration / 1000));

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }
}
