package eu.europa.esig.dss.token;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
@AllArgsConstructor
public class CustomKeyStoreToken extends AbstractKeyStoreTokenConnection {

	
   @NonNull protected KeyStore keyStore;
	   protected PasswordProtection keyProtectionParameter;
	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}


	 
}
