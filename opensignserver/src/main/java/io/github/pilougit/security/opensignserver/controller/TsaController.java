package io.github.pilougit.security.opensignserver.controller;

import java.io.InputStream;

import org.bouncycastle.tsp.TimeStampResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.github.pilougit.security.tsa.service.TsaService;
import lombok.extern.slf4j.Slf4j;
@RestController
@RequestMapping("/tsa")
@Slf4j
public class TsaController
{
	@Autowired 
	private TsaService tsaService;
	
	@PostMapping(
            consumes = "application/timestamp-query",
            produces = "application/timestamp-reply")
public ResponseEntity<byte[]> sign(InputStream requestInputStream) throws Exception {
	TsaController.log.debug("Signing Stream");
	TimeStampResponse responseData = this.tsaService.timestamp(requestInputStream);
   return ResponseEntity.ok(responseData.getEncoded());
}
}