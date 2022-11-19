package io.github.pilougit.security.certificate.service;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.Date;

import java.security.cert.Certificate;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import io.github.pilougit.security.certificate.configuration.GeneratedCert;
import io.github.pilougit.security.certificate.model.CreateCertificateCommand;

@Slf4j
@Service
public class CertificateService {

	String SIGNATURE_ALGORITHM = "SHA256withRSA";
	@Autowired
	KeyStore store;

	public GeneratedCert getGenerateCert(String alias, char[] password) throws CertificateException {
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) this.store.getCertificate(alias);

			PrivateKey key = (PrivateKey) this.store.getKey(alias, password);
			return new GeneratedCert(key, certificate);
		} catch (KeyStoreException e) {
			throw new CertificateException(e);
		} catch (UnrecoverableKeyException e) {
			throw new CertificateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException(e);
		}
	}

	public X509Certificate getGenerateCert(String alias)
			throws CertificateException {
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) this.store.getCertificate(alias);
			return certificate;
		} catch (KeyStoreException e) {
			throw new CertificateException(e);
		}
		
	}
	public Certificate [] getGenerateCertChain(String alias)
			throws CertificateException {
		Certificate [] certificate;
		try {
			certificate =  this.store.getCertificateChain(alias);
			return certificate;
		} catch (KeyStoreException e) {
			throw new CertificateException(e);
		}
		
	}

	public GeneratedCert createSelfSignedCertificate(CreateCertificateCommand command)
			throws CertificateException {
		try{
			ZoneId defaultZoneId = ZoneId.systemDefault();
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(command.getKeyType(), "BC");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
				.build(keyPair.getPrivate());
		X500Name owner = new X500Name(command.getDn());
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(owner,
				new BigInteger(64, new SecureRandom()),
				Date.from(command.getValidityBeginDate().atStartOfDay(defaultZoneId).toInstant()),
				Date.from(command.getValidityEndDate().atStartOfDay(defaultZoneId).toInstant()), owner,
				keyPair.getPublic());
		JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
		builder.addExtension(Extension.subjectKeyIdentifier, false,
				rootCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
		X509CertificateHolder certificateHolder = builder.build(sigGen);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		cert.verify(keyPair.getPublic());
		return new GeneratedCert(keyPair.getPrivate(), cert);
		}catch ( Exception e)
		{
			throw new CertificateException(e);
		}
	}

	public GeneratedCert createSigningCertificate(CreateCertificateCommand command, GeneratedCert rootCert)
			throws CertificateException, NoSuchAlgorithmException, CertIOException, OperatorCreationException,
			NoSuchProviderException, InvalidKeyException, SignatureException {
		X500Name issuedCertSubject = new X500Name(command.getDn());
		X500Name issuerName = new X500Name(rootCert.getCertificate().getSubjectDN().getName());

		ZoneId defaultZoneId = ZoneId.systemDefault();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(command.getKeyType(), "BC");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject,
				keyPair.getPublic());
		ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
				.build(keyPair.getPrivate());
		PKCS10CertificationRequest csr = p10Builder.build(sigGen);

		X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(issuerName,
				new BigInteger(64, new SecureRandom()),
				Date.from(command.getValidityBeginDate().atStartOfDay(defaultZoneId).toInstant()),
				Date.from(command.getValidityEndDate().atStartOfDay(defaultZoneId).toInstant()), csr.getSubject(),
				csr.getSubjectPublicKeyInfo());

		JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
		issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
		issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert.getCertificate()));
		issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
		issuedCertBuilder.addExtension(Extension.keyUsage, false, ku);

		X509CertificateHolder certificateHolder = issuedCertBuilder.build(sigGen);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		cert.verify(keyPair.getPublic());
		return new GeneratedCert(keyPair.getPrivate(), cert);
	}

	public GeneratedCert createTimeStampCertificate(CreateCertificateCommand command, GeneratedCert rootCert)
			throws CertificateException, NoSuchAlgorithmException, CertIOException, OperatorCreationException,
			NoSuchProviderException, InvalidKeyException, SignatureException {
		X500Name issuedCertSubject = new X500Name(command.getDn());
		X500Name issuerName = new X500Name(rootCert.getCertificate().getSubjectDN().getName());

		ZoneId defaultZoneId = ZoneId.systemDefault();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(command.getKeyType(), "BC");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject,
				keyPair.getPublic());
		ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider("BC")
				.build(keyPair.getPrivate());
		PKCS10CertificationRequest csr = p10Builder.build(sigGen);

		X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(issuerName,
				new BigInteger(64, new SecureRandom()),
				Date.from(command.getValidityBeginDate().atStartOfDay(defaultZoneId).toInstant()),
				Date.from(command.getValidityEndDate().atStartOfDay(defaultZoneId).toInstant()), csr.getSubject(),
				csr.getSubjectPublicKeyInfo());

		issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature);
		issuedCertBuilder.addExtension(Extension.extendedKeyUsage, true,
				new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
		issuedCertBuilder.addExtension(Extension.keyUsage, false, ku);

		X509CertificateHolder certificateHolder = issuedCertBuilder.build(sigGen);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		cert.verify(keyPair.getPublic());
		return new GeneratedCert(keyPair.getPrivate(), cert);
	}
}
