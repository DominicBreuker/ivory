// SChannelPeer is the .NET side of ivory's Windows SChannel interop
// tests: a TLS server or client on SslStream, which uses SChannel on
// Windows. It authenticates with a Brainpool identity, requires a
// certificate from the peer that chains to the given CA, exchanges one
// line, and prints what was negotiated as one JSON line. It exits with
// status 1 if anything fails.
//
// Usage: SChannelPeer server|client --addr host:port --version 1.2|1.3|default
//        --cert cert.pem --key key.pem --ca ca.pem [--servername localhost]

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

var opts = new Dictionary<string, string>();
if (args.Length < 1 || (args[0] != "server" && args[0] != "client"))
{
    Console.Error.WriteLine("usage: SChannelPeer server|client --addr host:port --version 1.2|1.3 --cert c.pem --key k.pem --ca ca.pem");
    return 2;
}
var role = args[0];
for (int i = 1; i + 1 < args.Length; i += 2)
{
    opts[args[i].TrimStart('-')] = args[i + 1];
}
var result = new Dictionary<string, object?> { ["role"] = role };
try
{
    await Run();
    Console.WriteLine(JsonSerializer.Serialize(result));
    return 0;
}
catch (Exception e)
{
    result["error"] = e.ToString();
    Console.WriteLine(JsonSerializer.Serialize(result));
    return 1;
}

async Task Run()
{
    var protocol = opts.GetValueOrDefault("version", "1.2") switch
    {
        "1.2" => SslProtocols.Tls12,
        "1.3" => SslProtocols.Tls13,
        // The system's choice: TLS 1.2 and 1.3 on current Windows.
        "default" => SslProtocols.None,
        var v => throw new ArgumentException($"unknown version {v}"),
    };
    // SChannel needs the private key in a key container: an ephemeral key
    // from a PEM file doesn't work for a server credential, so the identity
    // goes through PKCS #12.
    using var pem = X509Certificate2.CreateFromPemFile(opts["cert"], opts["key"]);
    var identity = new X509Certificate2(pem.Export(X509ContentType.Pkcs12), (string?)null,
        X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
    var ca = X509Certificate2.CreateFromPem(File.ReadAllText(opts["ca"]));
    var (host, port) = SplitAddr(opts.GetValueOrDefault("addr", "127.0.0.1:4433"));
    var timeout = TimeSpan.FromSeconds(60);

    bool Validate(object sender, X509Certificate? cert, X509Chain? _, SslPolicyErrors errors)
    {
        if (cert == null)
        {
            result["validation"] = "no peer certificate";
            return false;
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        var leaf = new X509Certificate2(cert);
        var ok = chain.Build(leaf);
        result["peer_subject"] = leaf.Subject;
        result["peer_key"] = leaf.PublicKey.Oid.FriendlyName;
        if (!ok)
        {
            result["validation"] = string.Join("; ", chain.ChainStatus.Select(s => s.Status + ": " + s.StatusInformation.Trim()));
            return false;
        }
        // The chain is checked above; only the name check of SslStream
        // still counts.
        var rest = errors & ~(SslPolicyErrors.RemoteCertificateChainErrors);
        result["validation"] = rest == SslPolicyErrors.None ? "ok" : rest.ToString();
        return rest == SslPolicyErrors.None;
    }

    SslStream ssl;
    using var cts = new CancellationTokenSource(timeout);
    if (role == "server")
    {
        var listener = new TcpListener(IPAddress.Parse(host), port);
        listener.Start();
        Console.Error.WriteLine($"SChannelPeer: listening on {listener.LocalEndpoint}");
        var client = await listener.AcceptTcpClientAsync(cts.Token);
        listener.Stop();
        ssl = new SslStream(client.GetStream(), false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = identity,
            ClientCertificateRequired = true,
            EnabledSslProtocols = protocol,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = Validate,
        }, cts.Token);
    }
    else
    {
        var client = new TcpClient();
        await client.ConnectAsync(host, port, cts.Token);
        ssl = new SslStream(client.GetStream(), false);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = opts.GetValueOrDefault("servername", "localhost"),
            ClientCertificates = new X509CertificateCollection { identity },
            LocalCertificateSelectionCallback = (_, _, _, _, _) => identity,
            EnabledSslProtocols = protocol,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = Validate,
        }, cts.Token);
    }
    using (ssl)
    {
        result["version"] = ssl.SslProtocol.ToString();
        result["suite"] = ssl.NegotiatedCipherSuite.ToString();
        result["local_certificate"] = ssl.LocalCertificate?.Subject;
        var reader = new StreamReader(ssl, Encoding.ASCII);
        if (role == "client")
        {
            await ssl.WriteAsync(Encoding.ASCII.GetBytes("hello from schannel\n"), cts.Token);
            var line = await reader.ReadLineAsync(cts.Token);
            if (line != "hello from ivory") throw new Exception($"unexpected reply {line}");
        }
        else
        {
            var line = await reader.ReadLineAsync(cts.Token);
            if (line != "hello from ivory") throw new Exception($"unexpected message {line}");
            await ssl.WriteAsync(Encoding.ASCII.GetBytes("hello from schannel\n"), cts.Token);
        }
        await ssl.ShutdownAsync();
    }
}

static (string, int) SplitAddr(string addr)
{
    var i = addr.LastIndexOf(':');
    return (addr[..i], int.Parse(addr[(i + 1)..]));
}
