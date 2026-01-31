package com.atwo.paganois;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import com.atwo.paganois.config.RateLimitConfig;

@SpringBootApplication
@EnableScheduling
@EnableAsync
@EnableConfigurationProperties(RateLimitConfig.class)
public class PaganoisApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaganoisApplication.class, args);
    }

}
