package com.atwo.paganois.dtos;

import io.swagger.v3.oas.annotations.media.Schema;

public record RegisterResponse(

        @Schema(description = "ID do usuário criado", example = "1") Long id,

        @Schema(description = "Username do usuário", example = "usuariodasilva") String username,

        @Schema(description = "Status de verificação do email", example = "false") boolean isEmailVerified) {

}