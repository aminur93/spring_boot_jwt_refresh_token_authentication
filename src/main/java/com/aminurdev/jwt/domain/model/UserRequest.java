package com.aminurdev.jwt.domain.model;

import com.aminurdev.jwt.domain.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {

    private Integer id;
    private String name;
    private String email;
    private String password;
    private Role role;
}
