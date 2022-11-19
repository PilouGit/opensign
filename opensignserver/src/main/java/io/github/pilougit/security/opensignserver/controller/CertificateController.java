package io.github.pilougit.security.opensignserver.controller;

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import io.github.pilougit.security.certificate.configuration.GeneratedCert;
import io.github.pilougit.security.certificate.model.CreateCertificateCommand;
import io.github.pilougit.security.certificate.service.CertificateService;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("certificate")
@Slf4j
public class CertificateController {

	@Autowired
	CertificateService certificateService;

	@Autowired  KeyStore keyStore;
	@GetMapping(path="/{alias}",produces = "application/text")
	@ResponseBody
	public ResponseEntity<String> getCertificate(@PathVariable String alias) {
		X509Certificate x509Certificate;
		try {
			x509Certificate = certificateService.getGenerateCert(alias);
			StringWriter sw = new StringWriter();
			try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
				writer.writeObject(x509Certificate);
				writer.flush();
				writer.close();
				return ResponseEntity.ok(sw.toString());
			} catch (IOException e) {
				return ResponseEntity.badRequest().body(e.getMessage());
			}
		} catch (CertificateException e1) {
			return ResponseEntity.notFound().build();
		}

	}
	@GetMapping(path="/{alias}/chain",produces = "application/text")
	@ResponseBody
	public ResponseEntity<String> getCertificateChain(@PathVariable String alias) {
		Certificate [] certificateArray;
		try {
			certificateArray = certificateService.getGenerateCertChain(alias);
			StringWriter sw = new StringWriter();
			try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
				for (Certificate certificate:certificateArray)
				writer.writeObject(certificate);
				writer.flush();
				writer.close();
				return ResponseEntity.ok(sw.toString());
			} catch (IOException e) {
				return ResponseEntity.badRequest().body(e.getMessage());
			}
		} catch (CertificateException e1) {
			return ResponseEntity.notFound().build();
		}

	}
	@PostMapping(consumes = "application/json",
            produces = "application/text")
	@ResponseBody
	public ResponseEntity<String> generateSelfSignedCertificate(@RequestBody CreateCertificateCommand certificateCommand) throws UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, CertIOException, OperatorCreationException, NoSuchProviderException, SignatureException
	{
		try {
			GeneratedCert certificate;
			Certificate [] certificateChain;
			if (StringUtils.isNoneBlank(certificateCommand.getIssuerCertificateName()))
			{
				X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(certificateCommand.getIssuerCertificateName());
				PrivateKey key = (PrivateKey) keyStore.getKey(certificateCommand.getIssuerCertificateName(), certificateCommand.getIssuerCertificatePassword());
				
				GeneratedCert cert=new GeneratedCert(key,issuerCertificate);
				certificate=certificateService.createSigningCertificate(certificateCommand, cert);
				Certificate[] issuerCertificateChain = keyStore.getCertificateChain(certificateCommand.getIssuerCertificateName());
					certificateChain=new Certificate[issuerCertificateChain.length+1];
				System.arraycopy(issuerCertificateChain, 0, certificateChain, 0, issuerCertificateChain.length);
				
				certificateChain[issuerCertificateChain.length]=certificate.getCertificate();
				
				
			}
			else
				{
				certificate = certificateService.createSelfSignedCertificate(certificateCommand);
				certificateChain=new Certificate[1];
				certificateChain[0]=certificate.getCertificate();
				
				}
			keyStore.setCertificateEntry(certificateCommand.getCertificateName(), certificate.getCertificate());
			
			keyStore.setKeyEntry(certificateCommand.getCertificateName(), certificate.getPrivateKey(), certificateCommand.getPassword(), certificateChain);
			return getCertificate(certificateCommand.getCertificateName());
		
		} catch (CertificateException e) {
			return ResponseEntity.internalServerError().body(e.getMessage());
		} catch (KeyStoreException e) {
			return ResponseEntity.internalServerError().body(e.getMessage());
		}
	}
}
