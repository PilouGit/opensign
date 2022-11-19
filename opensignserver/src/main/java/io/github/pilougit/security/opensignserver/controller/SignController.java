package io.github.pilougit.security.opensignserver.controller;

import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import io.github.pilougit.security.sign.model.PdfToBeSigned;
import io.github.pilougit.security.sign.service.SignService;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("sign")
@Slf4j
public class SignController {

	@Autowired 
	SignService signService;
	@PostMapping (consumes = MediaType.APPLICATION_PDF_VALUE,
            produces = MediaType.APPLICATION_PDF_VALUE)
	public ResponseEntity<byte[]> displayHeaderInfo(
			@RequestHeader("login") String loginBase64,
            @RequestHeader("password") String passwordBase64,
            @RequestParam("file") MultipartFile file)  {
		
		String login=new String(Base64.getDecoder().decode(loginBase64));
		byte [] passwordAsByte=Base64.getDecoder().decode(passwordBase64);
		char [] password=new char[passwordAsByte.length];
		for (int i=0;i<password.length;i++)
		{
			password[i]=(char) passwordAsByte[i];
		}
		try {
			return ResponseEntity.ok(signService.signPDF(new PdfToBeSigned(login,password,file.getBytes())));
		} catch (KeyStoreException | IOException e) {
			  throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Problem",e);
		}
		
	}
	
	
}
