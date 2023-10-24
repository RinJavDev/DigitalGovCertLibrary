package ru.digitalGovCert.library;

import android.content.Context;
import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

final class CertLoader
{
	private final @NonNull Context context;
	private final @NonNull CertificateFactory certificateFactory;

	public CertLoader(final @NonNull Context context, final @NonNull CertificateFactory certificateFactory)
	{
		this.context = context;
		this.certificateFactory = certificateFactory;
	}

	final @Nullable Certificate getRawCert(@NonNull String rawResourceName)
	{
		final InputStream subIns = readPemCert(rawResourceName);
		try
		{
			return certificateFactory.generateCertificate(subIns);
		}
		catch (CertificateException e)
		{
			return null;
		}
	}

	final @NonNull ArrayList<X509Certificate> getSystemCerts() throws Exception
	{
		final ArrayList<X509Certificate> certificates = new ArrayList<>();

		final KeyStore ks = KeyStore.getInstance("AndroidCAStore");

		if (ks != null)
		{
			ks.load(null, null);
			final Enumeration<String> aliases = ks.aliases();

			while (aliases.hasMoreElements())
			{
				try
				{

					final String alias = aliases.nextElement();
					final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

					certificates.add(cert);
				}
				catch (Throwable throwable)
				{
					throwable.printStackTrace();
				}
			}
		}

		return certificates;
	}

	private final InputStream readPemCert(final @NonNull String certName)
	{
		return fromPem(getPemAsString(certName));
	}

	private final String getPemAsString(final @NonNull String certName)
	{
		final InputStream ins = context.getResources().openRawResource(
				context.getResources().getIdentifier(
						certName, "raw", context.getPackageName()));
		StringBuilder textBuilder = new StringBuilder();
		try (Reader reader = new BufferedReader(new InputStreamReader
														(ins, Charset.forName(StandardCharsets.UTF_8.name()))))
		{
			int c = 0;
			while ((c = reader.read()) != -1)
			{
				textBuilder.append((char) c);
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		return textBuilder.toString();
	}

	private @NonNull InputStream fromPem(final @NonNull String pem)
	{
		String base64cert = pemKeyContent(pem);
		return fromBase64String(base64cert);
	}

	private final @NonNull InputStream fromBase64String(final @NonNull String base64cert)
	{
		byte[] decoded = Base64.decode(base64cert, Base64.NO_WRAP);
		return new ByteArrayInputStream(decoded);
	}

	private final @NonNull String pemKeyContent(final @NonNull String pem)
	{
		return pem.replace("\\s+", "")
				  .replace("\n", "")
				  .replace("-----BEGIN PUBLIC KEY-----", "")
				  .replace("-----END PUBLIC KEY-----", "")
				  .replace("-----BEGIN CERTIFICATE-----", "")
				  .replace("-----END CERTIFICATE-----", "");
	}
}
