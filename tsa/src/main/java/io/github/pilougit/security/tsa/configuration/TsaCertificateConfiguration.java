package io.github.pilougit.security.tsa.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.security.*;
import java.security.cert.X509Certificate;

@Configuration
@Validated
@ConfigurationProperties(prefix="tsa")
@Getter
@Setter
public class TsaCertificateConfiguration {
    char [] certificatePassword;
    String certificateAlias;
   
}
