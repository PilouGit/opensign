package io.github.pilougit.security.sign.model;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.token.CustomKeyStoreToken;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;

@Data
@AllArgsConstructor
public class PdfToBeSigned {

	@NonNull String alias;
	@NonNull  char [] password;
	@NonNull  byte [] data;
	
	
}
