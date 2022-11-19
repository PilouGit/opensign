package io.github.pilougit.security.tsa;

import io.github.pilougit.security.tsa.service.TsaService;
import lombok.NonNull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;

@SpringBootTest(classes = Application.class)
class TsaApplicationTests {



	@Test
	public void contextLoads(@Autowired
					  TsaService tsaService) throws Exception {
			final String resourcePath = "src/test/resources";
			final File ressourcesTests = new File(resourcePath);
			File f=new File(ressourcesTests,"application.properties");

			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			byte[] hashValue = digest.digest(Files.readAllBytes(f.toPath()));
			// Setup the time stamp request
			TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
			tsqGenerator.setCertReq(true);
			BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
			TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), hashValue, nonce);

			TimeStampResponse response = tsaService.timestamp(request.getEncoded());
			response.getTimeStampToken();
	}

}
