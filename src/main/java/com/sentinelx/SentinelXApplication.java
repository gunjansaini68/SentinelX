package com.sentinelx;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the SentinelX application.
 *
 * @SpringBootApplication is a shortcut that enables three things:
 *   1. Auto-configuration  – Spring Boot guesses and sets up sensible defaults.
 *   2. Component scanning  – Spring finds all @Service, @RestController, etc. classes
 *                            inside the com.sentinelx package automatically.
 *   3. Configuration support – allows @Value and application.properties to work.
 *
 * Running main() starts an embedded Tomcat server on http://localhost:8080.
 */
@SpringBootApplication
public class SentinelXApplication {

    public static void main(String[] args) {
        SpringApplication.run(SentinelXApplication.class, args);
    }
}
