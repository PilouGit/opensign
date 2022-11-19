package io.github.pilougit.security.sign;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.github.pilougit.security.sign.model.PdfToBeSigned;
import io.github.pilougit.security.sign.service.SignService;



@SpringBootTest(classes = Application.class)
public class SignApplicationTests {
	
	@Test
	public void contextLoadsPDF(@Autowired
					  SignService signService) throws Exception {
		   String filename="/home/pilou/PilouSign/opensign/sign/src/test/resources/Test2.pdf";
		   String filenametest="/home/pilou/PilouSign/opensign/sign/src/test/resources/SignTest3.pdf";
		   FileUtils.deleteQuietly(new File(filenametest));
		   
			   
		     
	}
	
}
