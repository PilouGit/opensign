package io.github.pilougit.security.tsa;

import io.github.pilougit.security.tsa.service.TsaService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

@Configuration
public class KeyStoreProvider {
    private static final String BC_PROVIDER = "BC";
    @Bean
    TsaService myService() {
        return new TsaService();
    }
    @Bean
    public KeyStore getKeyStore() throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        String type="PKCS12";
        String filename="/home/pilou/PilouSign/PilouSign/keystore2.pfx";
        String password="pilou";

        KeyStore sslKeyStore = KeyStore.getInstance(type, BC_PROVIDER);
        sslKeyStore.load(new FileInputStream(filename), password.toCharArray());
        return sslKeyStore;

    }
}
