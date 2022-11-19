package io.github.pilougit.security.sign.service;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.CustomKeyStoreToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import lombok.extern.slf4j.Slf4j;
import io.github.pilougit.security.sign.configuration.SignConfiguration;
import io.github.pilougit.security.sign.model.PdfToBeSigned;


@Service
@Slf4j
public class SignService {

	
	@Autowired
	KeyStore keyStore;
	
	@Autowired
	SignConfiguration signCertificateConfiguration;

	public PAdESService createPAdESService()
	{
		 CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
	    PAdESService service = new PAdESService(commonCertificateVerifier);
		if (StringUtils.isNoneBlank(signCertificateConfiguration.getTsaUrl()))
		{
			
			 OnlineTSPSource tspSource = new OnlineTSPSource(signCertificateConfiguration.getTsaUrl());
		     tspSource.setDataLoader(new TimestampDataLoader());
		     service.setTspSource(tspSource);
		}
		 return service;
	}
	public PAdESSignatureParameters createPAdESSignatureParameters(CertificateToken signerCert)
	{
		 PAdESSignatureParameters parameters = new PAdESSignatureParameters();
         parameters.setSigningCertificate(signerCert);
         if (StringUtils.isNoneBlank(signCertificateConfiguration.getTsaUrl()))
 		{ parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
 		}else
		{
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		       
		}
         return parameters;
	}

    public byte [] signPDF (PdfToBeSigned pdfToBeSigned) throws KeyStoreException, IOException
    {
    	CustomKeyStoreToken token=new CustomKeyStoreToken(
    			keyStore,null
    			);
    	 DSSDocument toSignDocument =  new InMemoryDocument(pdfToBeSigned.getData());
    	 DSSPrivateKeyEntry privateKey= token.getKey(pdfToBeSigned.getAlias()
        		  , new PasswordProtection(pdfToBeSigned.getPassword()));
          
         CertificateToken signerCert = privateKey.getCertificate();
         PAdESService  service = createPAdESService();
         PAdESSignatureParameters parameters = createPAdESSignatureParameters(signerCert);
      
         ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
         SignatureValue signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA256, privateKey);
         DSSDocument signedFile = service.signDocument(toSignDocument, parameters, signatureValue);
         byte [] result=IOUtils.toByteArray(signedFile.openStream());
         
         token.close();
         return result;
    }
	
}
