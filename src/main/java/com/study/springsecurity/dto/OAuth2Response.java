package com.study.springsecurity.dto;

import com.study.springsecurity.enums.OAuth2Status;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
public class OAuth2Response {
    private OAuth2Status status;
    private String message;
    private LocalDateTime timestamp;

}
