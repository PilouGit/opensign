package io.github.pilougit.security.opensignserver;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import io.github.pilougit.security.databasekeystore.DatabaseKeyStoreProvider;

@SpringBootApplication
@ComponentScan(basePackages = { "io.github.pilougit.security"})
public class OpenSignApplication {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new DatabaseKeyStoreProvider());
		SpringApplication.run(OpenSignApplication.class, args);
	}
}
