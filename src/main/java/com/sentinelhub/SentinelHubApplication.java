package com.sentinelhub;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SentinelHubApplication {

    public static void main(String[] args) {
        SpringApplication.run(SentinelHubApplication.class, args);
    }
}
