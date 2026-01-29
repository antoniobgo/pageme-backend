package com.atwo.paganois.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import com.atwo.paganois.services.CustomUserDetailsService;

@Component
public class ScheduledTasks {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Scheduled(cron = "0 0 3 * * *")
    public void cleanupExpiredUnverifiedUsers() {
        int daysToExpire = 7;

        logger.info("Iniciando limpeza de usuários não verificados (>{} dias)", daysToExpire);

        int deletedCount = userDetailsService.cleanupExpiredUnverifiedUsers(daysToExpire);

        logger.info("Limpeza concluída: {} usuários não verificados removidos", deletedCount);
    }
}
