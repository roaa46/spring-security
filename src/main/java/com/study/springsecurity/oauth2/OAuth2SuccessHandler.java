package com.study.springsecurity.oauth2;

import com.study.springsecurity.entity.User;
import com.study.springsecurity.enums.Role;
import com.study.springsecurity.repository.UserRepository;
import com.study.springsecurity.service.JwtService;
import com.study.springsecurity.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
        String email = (String) oauthUser.getAttributes().get("email");
        String firstName = (String) oauthUser.getAttributes().get("given_name");
        String lastName = (String) oauthUser.getAttributes().get("family_name");
        if (email == null) {
            email = oauthUser.getName();
        }
        String finalEmail = email;
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(finalEmail)
                            .firstName(firstName != null ? firstName : "")
                            .lastName(lastName != null ? lastName : "")
                            .password("oauth2_user")
                            .role(Role.USER)
                            .oauth2User(true)
                            .build();
                    return userRepository.save(newUser);
                });


        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        tokenService.revokeAllUserTokens(user);
        tokenService.saveUserToken(user, accessToken);
        tokenService.addTokenCookies(response, accessToken, refreshToken);

//        response.sendRedirect("http://localhost:3000/oauth-success");

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String jsonResponse = String.format(
                "{\"access_token\": \"%s\", \"refresh_token\": \"%s\"}",
                accessToken,
                refreshToken
        );

        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
}