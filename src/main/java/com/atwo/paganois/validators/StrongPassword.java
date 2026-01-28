package com.atwo.paganois.validators;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = StrongPasswordValidator.class)
public @interface StrongPassword {
    String message() default "Senha deve conter: mínimo 8 caracteres, 1 maiúscula, 1 minúscula, 1 número e 1 caractere especial";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}


