// BCPeer is a TLS client or server on BouncyCastle's JSSE provider (BCJSSE)
// for ivory's interop tests (interop/bc_test.go). It makes one connection,
// prints what was negotiated, and exchanges one line with the peer, once
// or for -connections n, n times in a row with the same SSLContext.
//
//   java -cp <dir>:<BouncyCastle jars> BCPeer server|client [flags]
//
// Flags:
//   -addr host:port      server: listen there; client: connect there
//   -cert f[,f] -key f[,f]  own certificates and PKCS #8 or SEC 1 keys
//                        (PEM), one identity per pair; BCJSSE picks one
//   -ca f[,f]            trusted CA certificates (PEM)
//   -protocol p          TLSv1.2 or TLSv1.3
//   -groups g,g          named groups in preference order, as BCJSSE names
//                        them (secp256r1, brainpoolP256r1, brainpoolP256r1tls13, ...)
//   -suites s,s          cipher suites (default: BCJSSE's)
//   -clientauth          server: require a client certificate
//   -servername name     client: check the server certificate for this name
//   -connections n       make (client) or accept (server) n connections
//
// Output, one line each: "listening <addr>" (server), then after the
// handshake "protocol <p>", "suite <s>", "peer <subject>", "local
// <subject>" (the own certificate sent, or "none"), "session <id>" (hex),
// then "received <line>" when the peer's line arrived, or "error
// <message>".
// The server reads a line from the client; the client reads a line from
// the server. Exit status 0 on success.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class BCPeer {
	// A strong reference, so that the level set in run sticks.
	static final java.util.logging.Logger BC_LOG = java.util.logging.Logger.getLogger("org.bouncycastle");

	public static void main(String[] args) {
		try {
			run(args);
		} catch (Exception e) {
			System.out.println("error " + e);
			System.out.flush();
			System.exit(1);
		}
	}

	static void run(String[] args) throws Exception {
		if (args.length < 1 || !(args[0].equals("server") || args[0].equals("client"))) {
			throw new IllegalArgumentException("usage: BCPeer server|client [flags]");
		}
		boolean server = args[0].equals("server");
		Map<String, String> f = new HashMap<>();
		for (int i = 1; i < args.length; i++) {
			if (args[i].equals("-clientauth")) {
				f.put("clientauth", "");
			} else if (args[i].startsWith("-") && i + 1 < args.length) {
				f.put(args[i].substring(1), args[++i]);
			} else {
				throw new IllegalArgumentException("bad flag " + args[i]);
			}
		}

		// BCJSSE logs JDK security settings it doesn't understand.
		BC_LOG.setLevel(java.util.logging.Level.SEVERE);

		// BCJSSE reads the groups from this property when the context is
		// created.
		if (f.containsKey("groups")) {
			System.setProperty("jdk.tls.namedGroups", f.get("groups"));
		}
		BouncyCastleProvider bc = new BouncyCastleProvider();
		Security.insertProviderAt(bc, 1);
		Security.insertProviderAt(new BouncyCastleJsseProvider(bc), 2);

		CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
		KeyManagerFactory kmf = null;
		if (f.containsKey("cert")) {
			String[] certs = f.get("cert").split(","), keys = f.get("key").split(",");
			if (certs.length != keys.length) {
				throw new IllegalArgumentException("-cert and -key differ in length");
			}
			KeyStore ks = KeyStore.getInstance("PKCS12", bc);
			ks.load(null, null);
			for (int i = 0; i < certs.length; i++) {
				List<Certificate> chain = new ArrayList<>(cf.generateCertificates(Files.newInputStream(Path.of(certs[i]))));
				ks.setKeyEntry("id" + i, readKey(keys[i]), new char[0], chain.toArray(new Certificate[0]));
			}
			kmf = KeyManagerFactory.getInstance("PKIX", "BCJSSE");
			kmf.init(ks, new char[0]);
		}
		KeyStore trust = KeyStore.getInstance("PKCS12", bc);
		trust.load(null, null);
		int n = 0;
		for (String file : f.getOrDefault("ca", "").split(",")) {
			if (file.isEmpty()) {
				continue;
			}
			for (Certificate c : cf.generateCertificates(Files.newInputStream(Path.of(file)))) {
				trust.setCertificateEntry("ca" + n++, c);
			}
		}
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "BCJSSE");
		tmf.init(trust);

		SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");
		ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		String[] hp = f.get("addr").split(":");
		InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName(hp[0]), Integer.parseInt(hp[1]));
		int connections = Integer.parseInt(f.getOrDefault("connections", "1"));
		SSLServerSocket ss = null;
		if (server) {
			ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket();
			ss.bind(addr);
			System.out.println("listening " + f.get("addr"));
			System.out.flush();
		}
		for (int i = 0; i < connections; i++) {
			SSLSocket s;
			if (server) {
				s = (SSLSocket) ss.accept();
				s.setNeedClientAuth(f.containsKey("clientauth"));
			} else {
				s = (SSLSocket) ctx.getSocketFactory().createSocket(addr.getAddress(), addr.getPort());
				if (f.containsKey("servername")) {
					SSLParameters p = s.getSSLParameters();
					p.setEndpointIdentificationAlgorithm("HTTPS");
					p.setServerNames(List.of(new javax.net.ssl.SNIHostName(f.get("servername"))));
					s.setSSLParameters(p);
				}
			}
			connect(s, f);
		}
		if (ss != null) {
			ss.close();
		}
	}

	// connect runs the handshake on s and exchanges one line.
	static void connect(SSLSocket s, Map<String, String> f) throws Exception {
		s.setSoTimeout(20000);
		if (f.containsKey("protocol")) {
			s.setEnabledProtocols(new String[] {f.get("protocol")});
		}
		if (f.containsKey("suites")) {
			s.setEnabledCipherSuites(f.get("suites").split(","));
		}
		s.startHandshake();
		SSLSession session = s.getSession();
		System.out.println("protocol " + session.getProtocol());
		System.out.println("suite " + session.getCipherSuite());
		System.out.println("peer " + ((X509Certificate) session.getPeerCertificates()[0]).getSubjectX500Principal().getName());
		Certificate[] local = session.getLocalCertificates();
		System.out.println("local " + (local == null || local.length == 0 ? "none" : ((X509Certificate) local[0]).getSubjectX500Principal().getName()));
		System.out.println("session " + java.util.HexFormat.of().formatHex(session.getId()));
		System.out.flush();

		BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
		String line = in.readLine();
		if (line == null) {
			throw new java.io.EOFException("connection closed before a line arrived");
		}
		System.out.println("received " + line);
		System.out.flush();
		s.close();
	}

	static PrivateKey readKey(String file) throws Exception {
		try (Reader r = Files.newBufferedReader(Path.of(file)); PEMParser p = new PEMParser(r)) {
			Object o = p.readObject();
			JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider("BC");
			if (o instanceof PEMKeyPair) {
				return conv.getKeyPair((PEMKeyPair) o).getPrivate();
			}
			if (o instanceof PrivateKeyInfo) {
				return conv.getPrivateKey((PrivateKeyInfo) o);
			}
			throw new IllegalArgumentException(file + ": no private key");
		}
	}
}
