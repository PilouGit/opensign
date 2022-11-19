package io.github.pilougit.security.certificate.configuration;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDate;

import io.github.pilougit.security.certificate.model.CreateCertificateCommand;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;

@Data
@AllArgsConstructor
public class GeneratedCert {

	@NonNull protected final PrivateKey privateKey;
	@NonNull protected  final X509Certificate certificate;
}
