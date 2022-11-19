package io.github.pilougit.security.tsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

import java.security.Security;

@SpringBootApplication
@ComponentScan(basePackages = {"io.github.pilougit.security"})
public class Application {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(Application.class, args);
    }
}