package io.github.pilougit.security.opensignserver.configuration;

import io.github.pilougit.security.databasekeystore.DatabaseKeyStoreProvider;
import io.github.pilougit.security.databasekeystore.keystore.DatabaseKeyStoreLoadStoreParameter;
import io.github.pilougit.security.databasekeystore.keystore.repository.DatabaseKeyStoreJpaRepository;
import io.github.pilougit.security.databasekeystore.keystore.service.AESGcmCipheringKeyService;
import io.github.pilougit.security.tsa.service.TsaService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceUnit;

@Configuration
public class KeyStoreProvider {
    private static final String BC_PROVIDER = "BC";
    @Autowired 
    private EntityManagerFactory entityManagerFactory;
	private EntityManager entityManager;
    @Bean
    TsaService myService() {
        return new TsaService();
    }
    @PostConstruct
    public void init()
    {
    	this.entityManager=this.entityManagerFactory.createEntityManager();
    }
    @PreDestroy
    public void close()
    {
    	this.entityManager.close();
    }
    @Bean
    public KeyStore getKeyStore() throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        /*String type="PKCS12";
        String filename="/home/pilou/PilouSign/PilouSign/keystore2.pfx";
        String password="pilou";

        KeyStore sslKeyStore = KeyStore.getInstance(type, BC_PROVIDER);
        sslKeyStore.load(new FileInputStream(filename), password.toCharArray());
        return sslKeyStore;*/
        KeyStore keystore = KeyStore.getInstance(DatabaseKeyStoreProvider.KEYSTORE, DatabaseKeyStoreProvider.PROVIDER_NAME);
        keystore.load(new DatabaseKeyStoreLoadStoreParameter(new DatabaseKeyStoreJpaRepository(entityManager), new AESGcmCipheringKeyService()));
        
        return keystore;
    }
}
