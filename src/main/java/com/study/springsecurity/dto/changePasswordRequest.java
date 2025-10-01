package com.study.springsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class changePasswordRequest {
    private String currentPassword;
    private String newPassword;
    private String confirmationPassword;
}
