package com.study.springsecurity.service;

import com.study.springsecurity.dto.changePasswordRequest;
import com.study.springsecurity.entity.User;
import com.study.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String WRONG_PASSWORD_MESSAGE = "Current password is incorrect";
    private static final String PASSWORD_MISMATCH_MESSAGE = "New password and confirmation password do not match";
    private static final String SAME_PASSWORD_MESSAGE = "New password must be different from current password";
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void changePassword(changePasswordRequest request, Principal connectedUser) {
        User user = ((User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal());
        validatePasswordChange(request, user);
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    private void validatePasswordChange(changePasswordRequest request, User user) {
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException(WRONG_PASSWORD_MESSAGE);
        }
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException(PASSWORD_MISMATCH_MESSAGE);
        }
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new IllegalStateException(SAME_PASSWORD_MESSAGE);
        }
    }
}
