package com.atwo.paganois;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PaganoisApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaganoisApplication.class, args);
    }

}
