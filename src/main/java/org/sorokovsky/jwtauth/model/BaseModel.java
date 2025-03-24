package org.sorokovsky.jwtauth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BaseModel {
    private Long id;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
