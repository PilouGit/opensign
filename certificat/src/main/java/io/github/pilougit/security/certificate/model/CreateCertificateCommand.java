package io.github.pilougit.security.certificate.model;


import java.time.LocalDate;

import lombok.Data;
import lombok.NonNull;

@Data
public class CreateCertificateCommand {

	@NonNull protected  String certificateName;
	@NonNull protected String keyType;
	protected LocalDate validityBeginDate=LocalDate.now();
	 protected LocalDate validityEndDate=LocalDate.now().withYear(1);
	@NonNull protected String  dn;
	@NonNull protected char [] password;
	 protected  String issuerCertificateName;
	 protected  char [] issuerCertificatePassword;
	 protected CreateCertificateCommand()
	 {
		 
	 }
	public CreateCertificateCommand(@NonNull String certificateName, @NonNull String keyType,
			LocalDate validityBeginDate, LocalDate validityEndDate, @NonNull String dn, @NonNull char[] password) {
		super();
		this.certificateName = certificateName;
		this.keyType = keyType;
		if (validityBeginDate!=null)
		this.validityBeginDate = validityBeginDate;
		if (validityEndDate!=null)
			this.validityEndDate = validityEndDate;
		this.dn = dn;
		this.password = password;
	}
	public CreateCertificateCommand(@NonNull String certificateName, @NonNull String keyType,
			LocalDate validityBeginDate, LocalDate validityEndDate, @NonNull String dn, @NonNull char[] password,
			String issuerCertificateName, char[] issuerCertificatePassword) {
		this(certificateName,keyType,validityBeginDate,validityEndDate,dn,password);
		
		this.issuerCertificateName = issuerCertificateName;
		this.issuerCertificatePassword = issuerCertificatePassword;
	}
	
	
}
