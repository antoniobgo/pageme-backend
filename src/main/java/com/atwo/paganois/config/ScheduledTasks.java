package com.atwo.paganois.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import com.atwo.paganois.user.services.UserService;

@Component
public class ScheduledTasks {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);

    @Autowired
    private UserService userService;

    @Scheduled(cron = "0 32 16 * * *", zone = "America/Sao_Paulo")
    public void cleanupExpiredUnverifiedUsers() {
        int daysToExpire = 7;

        logger.info("Iniciando limpeza de usuários não verificados (>{} dias)", daysToExpire);
        try {
            int deletedCount = userService.cleanupExpiredUnverifiedUsers(daysToExpire);
            logger.info("Limpeza concluída: {} usuários não verificados removidos", deletedCount);
        } catch (Exception e) {
            logger.error("Erro ao tentar deletar usuários não verificados", e);
        }
    }
}
