package io.github.pilougit.security.tsa.configuration;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@Validated
@ConfigurationProperties(prefix="tsa")
@Getter
@Setter
public class TsaConfiguration {

    @NonNull
    String oid;
    @NonNull
    String digest;


    @Bean
    ASN1ObjectIdentifier tsaOid() {
        return new ASN1ObjectIdentifier(oid);
    }

    AlgorithmIdentifier digestAlgorithm() {
        DefaultDigestAlgorithmIdentifierFinder finder=new DefaultDigestAlgorithmIdentifierFinder();
        return finder.find(digest);
    }
    @Bean
    public DigestCalculator buildSignerCertDigestCalculator() throws Exception {
        return new JcaDigestCalculatorProviderBuilder().build()
                .get(digestAlgorithm());
    }
}
