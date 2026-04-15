package com.vladko.autoshopauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class AutoshopAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AutoshopAuthApplication.class, args);
    }

}
