package io.github.pilougit.security.certificate;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.time.LocalDate;

import org.apache.commons.io.FileUtils;
import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.github.pilougit.security.certificate.configuration.GeneratedCert;
import io.github.pilougit.security.certificate.model.CreateCertificateCommand;
import io.github.pilougit.security.certificate.service.CertificateService;



@SpringBootTest(classes = Application.class)
public class SignApplicationTests {
	
	@Autowired KeyStore keyStore;
	@Test
	public void contextLoadsPDF(@Autowired
			CertificateService certificateService) throws Exception {
		/*File f=new File("/home/pilou/PilouSign/PilouSign/keystore2.pfx");
		FileUtils.deleteQuietly(f); 
		
		CreateCertificateCommand createCertificateCACommand=new CreateCertificateCommand("casign",
				"RSA", "CN=root-cert","".toCharArray());
		CreateCertificateCommand createCertificateSignCommand=new CreateCertificateCommand("pdfsign",
				"RSA", "CN=sign","".toCharArray());
		CreateCertificateCommand tsaCommand=new CreateCertificateCommand("tsasign",
				"RSA", "CN=TSA","".toCharArray());
		
		GeneratedCert cert=certificateService.createSelfSignedCertificate(createCertificateCACommand);
		GeneratedCert cert2=certificateService.createSigningCertificate(createCertificateSignCommand,cert);
		GeneratedCert tsa=certificateService.createTimeStampCertificate(tsaCommand,cert);
			 KeyStore keystore2 = KeyStore.getInstance("PKCS12");
		 keystore2.load(null, "pilou".toCharArray());
		 keystore2.setCertificateEntry("casign", cert.getCertificate());
		 keystore2.setKeyEntry("casign", cert.getPrivateKey(), "pilou".toCharArray(), Arrays.array(cert.getCertificate()));
		 keystore2.setKeyEntry("pdfsign", cert2.getPrivateKey(), "pilou".toCharArray(), Arrays.array(cert2.getCertificate(),cert.getCertificate()));
		 keystore2.setKeyEntry("tsasign", tsa.getPrivateKey(), "pilou".toCharArray(), Arrays.array(tsa.getCertificate(),cert.getCertificate()));
				 keystore2.store(new FileOutputStream("/home/pilou/PilouSign/PilouSign/keystore2.pfx"),"pilou".toCharArray());
		*/     
	}
	
}
