package io.github.pilougit.security.tsa.service;

import io.github.pilougit.security.tsa.configuration.TsaCertificateConfiguration;
import io.github.pilougit.security.tsa.configuration.TsaConfiguration;
import org.apache.commons.io.input.UnsynchronizedByteArrayInputStream;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

@Service
public class TsaService {
    @Autowired
    TsaConfiguration tsaConfiguration;
    @Autowired
    TsaCertificateConfiguration certificateConfiguration;
    protected TimeStampResponseGenerator timeStampResponseGenerator;
    protected SecureRandom secureRandom = new SecureRandom();
    @Autowired
    KeyStore keyStore;

    public X509Certificate readTimeStampCertificate() throws KeyStoreException {
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(certificateConfiguration.getCertificateAlias());
        return x509Certificate;
    }

    public PrivateKey readTimeStampPrivateKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                certificateConfiguration.getCertificateAlias(), certificateConfiguration.getCertificatePassword());
        return privateKey;
    }

    protected SignerInfoGenerator buildSignerInfoGenerator() throws Exception {
        X509Certificate signingCertificate = readTimeStampCertificate();
        if (signingCertificate!=null) {
        String signingAlgorithmName = signingCertificate.getSigAlgName();
        PrivateKey signingPrivateKey = readTimeStampPrivateKey();
        return new JcaSimpleSignerInfoGeneratorBuilder().build(signingAlgorithmName, signingPrivateKey, signingCertificate);
        }
        else
        {
        	return null;
        }
        }

    protected TimeStampTokenGenerator buildTimeStampTokenGenerator(DigestCalculator digestCalulator, SignerInfoGenerator infoGenerator) throws IllegalArgumentException, TSPException {
        TimeStampTokenGenerator result = new TimeStampTokenGenerator(infoGenerator, digestCalulator,
                new ASN1ObjectIdentifier(tsaConfiguration.getOid()));
        return result;
    }
 
    @PostConstruct
    public void init() throws Exception {
    	SignerInfoGenerator signerInfoGenerator = buildSignerInfoGenerator();
    	if (signerInfoGenerator!=null) {
        TimeStampTokenGenerator timeStampTokenGenerator = 
        		buildTimeStampTokenGenerator(tsaConfiguration.buildSignerCertDigestCalculator()
                , signerInfoGenerator);
        JcaCertStore store=new JcaCertStore(Collections.singletonList(readTimeStampCertificate()));
        timeStampTokenGenerator.addCertificates(store);
        this.timeStampResponseGenerator = new TimeStampResponseGenerator(timeStampTokenGenerator, TSPAlgorithms.ALLOWED);
    	}
    }

    protected BigInteger generateSerial() {
        return BigInteger.valueOf(secureRandom.nextLong());
    }

    public TimeStampResponse timestamp(InputStream inputStream) throws Exception {
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        TimeStampReq timeStampReq = TimeStampReq.getInstance(asnInputStream.readObject());
        TimeStampRequest timeStampRequest = new TimeStampRequest(timeStampReq);
        BigInteger tspResponseSerial = generateSerial();
        TimeStampResponse tsResp = this.timeStampResponseGenerator.generate(timeStampRequest, tspResponseSerial, new Date());
        tsResp = new TimeStampResponse(tsResp.getEncoded());
        TimeStampToken tsToken = tsResp.getTimeStampToken();
        tsResp.validate(timeStampRequest);
        return tsResp;
    }

    public TimeStampResponse timestamp(byte [] byteArray) throws Exception {
    return this.timestamp(new UnsynchronizedByteArrayInputStream(byteArray));
    }
}