package ru.digitalGovCert.library;

import android.content.Context;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import androidx.annotation.NonNull;


/**
 * Сlass for working with SSL certificates that support Ministry of Digital Development certificates
 */
public final class CertManager
{
	private final @NonNull List<String> rawCertNames;

	public CertManager()
	{
		rawCertNames = new ArrayList<>();
		rawCertNames.add("russian_trusted_root_ca");
		rawCertNames.add("russian_trusted_sub_ca");
	}

	/**
	 * createCert and return {@link CertData}.
	 *
	 * @param context {@link Context}.
	 */
	public final @NonNull CertData createCertData(final @NonNull Context context) throws Exception
	{
		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);

		final CertLoader certLoader = new CertLoader(context, certificateFactory);
		for (String rawCertName : rawCertNames)
		{
			final Certificate rawCert = certLoader.getRawCert(rawCertName);
			if (rawCert != null)
			{
				try
				{
					keyStore.setCertificateEntry(rawCertName, rawCert);
				}
				catch (KeyStoreException e)
				{
					e.printStackTrace();
				}
			}
		}

		final ArrayList<X509Certificate> systemCerts = certLoader.getSystemCerts();
		for (X509Certificate certificate : systemCerts)
		{
			try
			{
				keyStore.setCertificateEntry(certificate.getIssuerDN().getName(), certificate);
			}
			catch (KeyStoreException e)
			{
				e.printStackTrace();
			}
		}

		final String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(tmfAlgorithm);
		trustManagerFactory.init(keyStore);

		final X509TrustManager x509TrustManager = findX509TrustManager(trustManagerFactory);
		final SSLContext sslContext = SSLContext.getInstance("SSL");

		sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

		return new CertData(x509TrustManager, sslContext, trustManagerFactory);
	}

	private final @NonNull X509TrustManager findX509TrustManager(final @NonNull TrustManagerFactory trustManagerFactory) throws Exception
	{

		for (TrustManager trustManager : trustManagerFactory.getTrustManagers())
		{
			if (trustManager instanceof X509TrustManager)
			{
				return (X509TrustManager) trustManager;
			}
		}
		throw new Exception("cannot find X509TrustManager in trustManagerFactory");
	}
}

