<#
.SYNOPSIS
    Installs the ClamAV console agent as the Windows service "ClamAVAgent".

.DESCRIPTION
    Downloads clamav-agent_windows_amd64.exe and its .minisig from
    <ServerUrl>/downloads/, VERIFIES THE MINISIGN SIGNATURE against the public
    key embedded below (never fetched from the server), installs the binary to
    %ProgramFiles%\ClamAVAgent, enrolls the machine, and registers a service
    running as the virtual account NT SERVICE\ClamAVAgent (not LocalSystem).

    Works on Windows PowerShell 5.1 and PowerShell 7. Run as Administrator.
    Idempotent: re-running upgrades the binary and keeps the enrollment.
    Use -Reinstall to enroll again (replacing this machine's agent).

    For a console with a private CA (e.g. a test VM), pass -CaSha256 with the
    SHA-256 fingerprint of the console's CA certificate. The CA is downloaded
    and used only if its fingerprint matches; downloads are then checked
    against that CA alone, and the agent trusts only that CA for the console.
    Later upgrade runs reuse the installed CA; -Reinstall uses only what it
    is given.

    -VerifyOnly checks a file against a signature and exits (no admin needed).

.EXAMPLE
    $env:CAV_ENROLL_TOKEN = 'cav_enr_...'
    .\install.ps1 -ServerUrl https://console.example.com

.EXAMPLE
    $env:CAV_ENROLL_TOKEN = 'cav_enr_...'
    .\install.ps1 -ServerUrl https://192.168.1.50 -CaSha256 3f1a...e9

.EXAMPLE
    .\install.ps1 -VerifyOnly -VerifyFile .\clamav-agent_windows_amd64.exe -VerifySignatureFile .\clamav-agent_windows_amd64.exe.minisig
#>
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$EnrollToken,
    [string]$ClamdAddress,
    [string]$CaSha256,
    [switch]$Reinstall,
    [switch]$VerifyOnly,
    [string]$VerifyFile,
    [string]$VerifySignatureFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Substituted by scripts/build-dist.sh. Release signing public key (minisign).
$MinisignPublicKey = '__MINISIGN_PUBKEY__'

# Fallbacks only matter off Windows (e.g. -VerifyOnly tests under pwsh on Linux).
$ProgramFilesDir = $env:ProgramFiles
if (-not $ProgramFilesDir) { $ProgramFilesDir = 'C:\Program Files' }
$ProgramDataDir = $env:ProgramData
if (-not $ProgramDataDir) { $ProgramDataDir = 'C:\ProgramData' }

$ServiceName   = 'ClamAVAgent'
$ServiceAcct   = 'NT SERVICE\ClamAVAgent'
$BinaryName    = 'clamav-agent_windows_amd64.exe'
$InstallDir    = [IO.Path]::Combine($ProgramFilesDir, 'ClamAVAgent')
$ExePath       = [IO.Path]::Combine($InstallDir, 'clamav-agent.exe')
$DataDir       = [IO.Path]::Combine($ProgramDataDir, 'ClamAVAgent')
$ConfigPath    = [IO.Path]::Combine($DataDir, 'agent.yaml')
$CredPath      = [IO.Path]::Combine($DataDir, 'credential')
$CaPath        = [IO.Path]::Combine($DataDir, 'console-ca.pem')
$LogDir        = [IO.Path]::Combine($DataDir, 'logs')
$SidAdmins     = '*S-1-5-32-544'
$SidSystem     = '*S-1-5-18'

# ---------------------------------------------------------------------------
# minisign verification. Windows has no built-in Ed25519 or BLAKE2b, so both
# are implemented here (C# 5 syntax so .NET Framework's csc can compile it).
# INTERIM: to be replaced by Authenticode verification (Get-AuthenticodeSignature)
# once a code-signing certificate exists. Tested against Wycheproof Ed25519 and
# BLAKE2b reference vectors by tests/Test-Verifier.ps1 (CI, PowerShell 5.1 + 7).
# ---------------------------------------------------------------------------
$CavMinisignSource = @'
using System;
using System.IO;
using System.Net.Security;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CavMinisign
{
    // Certificate checks for downloads from a console with a private CA.
    public static class Tls
    {
        // Accepts any certificate. Only for fetching the console CA, whose
        // fingerprint is checked before it is used.
        public static RemoteCertificateValidationCallback AcceptAny()
        {
            return delegate { return true; };
        }

        // Accepts the server only if its certificate is valid for the host
        // and chains to exactly this CA. The system trust store is not used.
        // The CA is loaded by New-CavCertificate: the byte[] constructor is
        // obsolete (an Add-Type error) on PowerShell 7.6, and its replacement
        // does not exist on Windows PowerShell 5.1.
        public static RemoteCertificateValidationCallback PinnedTo(X509Certificate2 ca)
        {
            return delegate (object sender, X509Certificate certificate, X509Chain presented, SslPolicyErrors errors)
            {
                return ChainsTo(ca, certificate, presented, errors);
            };
        }

        public static bool ChainsTo(X509Certificate2 ca, X509Certificate certificate, X509Chain presented, SslPolicyErrors errors)
        {
            if (certificate == null) { return false; }
            if ((errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) { return false; }
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // The CA is not in the system store; it is supplied here and
            // required to be the root below.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.ExtraStore.Add(ca);
            if (presented != null)
            {
                foreach (X509ChainElement e in presented.ChainElements) { chain.ChainPolicy.ExtraStore.Add(e.Certificate); }
            }
            if (!chain.Build(new X509Certificate2(certificate))) { return false; }
            if (chain.ChainElements.Count < 2) { return false; }
            byte[] root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate.RawData;
            byte[] want = ca.RawData;
            if (root.Length != want.Length) { return false; }
            for (int i = 0; i < root.Length; i++)
            {
                if (root[i] != want[i]) { return false; }
            }
            return true;
        }
    }

    public sealed class VerificationException : Exception
    {
        public VerificationException(string message) : base(message) { }
    }

    // BLAKE2b with a 64-byte digest and no key (RFC 7693).
    public sealed class Blake2b512
    {
        private static readonly ulong[] IV = new ulong[] {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL };

        private static readonly int[,] Sigma = new int[12, 16] {
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } };

        private readonly ulong[] h = new ulong[8];
        private readonly ulong[] m = new ulong[16];
        private readonly ulong[] v = new ulong[16];
        private readonly byte[] buf = new byte[128];
        private int bufLen;
        private ulong t0;
        private ulong t1;

        public Blake2b512()
        {
            for (int i = 0; i < 8; i++) { h[i] = IV[i]; }
            h[0] ^= 0x01010040UL; // digest length 64, key length 0, fanout 1, depth 1
        }

        public void Update(byte[] data, int offset, int count)
        {
            while (count > 0)
            {
                // Only compress a full buffer once more data arrives: the last
                // block must be compressed with the final flag.
                if (bufLen == 128)
                {
                    Increment(128);
                    Compress(false);
                    bufLen = 0;
                }
                int n = Math.Min(128 - bufLen, count);
                Buffer.BlockCopy(data, offset, buf, bufLen, n);
                bufLen += n;
                offset += n;
                count -= n;
            }
        }

        public byte[] Final()
        {
            Increment((ulong)bufLen);
            for (int i = bufLen; i < 128; i++) { buf[i] = 0; }
            Compress(true);
            byte[] output = new byte[64];
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++) { output[i * 8 + j] = (byte)(h[i] >> (8 * j)); }
            }
            return output;
        }

        public static byte[] HashStream(Stream s)
        {
            Blake2b512 b = new Blake2b512();
            byte[] chunk = new byte[65536];
            int n;
            while ((n = s.Read(chunk, 0, chunk.Length)) > 0) { b.Update(chunk, 0, n); }
            return b.Final();
        }

        private void Increment(ulong n)
        {
            unchecked
            {
                t0 += n;
                if (t0 < n) { t1++; }
            }
        }

        private static ulong Rotr(ulong x, int n)
        {
            return (x >> n) | (x << (64 - n));
        }

        private void G(int a, int b, int c, int d, ulong x, ulong y)
        {
            unchecked
            {
                v[a] = v[a] + v[b] + x; v[d] = Rotr(v[d] ^ v[a], 32);
                v[c] = v[c] + v[d];     v[b] = Rotr(v[b] ^ v[c], 24);
                v[a] = v[a] + v[b] + y; v[d] = Rotr(v[d] ^ v[a], 16);
                v[c] = v[c] + v[d];     v[b] = Rotr(v[b] ^ v[c], 63);
            }
        }

        private void Compress(bool last)
        {
            for (int i = 0; i < 16; i++)
            {
                ulong w = 0;
                for (int j = 7; j >= 0; j--) { w = (w << 8) | buf[i * 8 + j]; }
                m[i] = w;
            }
            for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
            v[12] ^= t0;
            v[13] ^= t1;
            if (last) { v[14] = ~v[14]; }
            for (int r = 0; r < 12; r++)
            {
                G(0, 4,  8, 12, m[Sigma[r, 0]],  m[Sigma[r, 1]]);
                G(1, 5,  9, 13, m[Sigma[r, 2]],  m[Sigma[r, 3]]);
                G(2, 6, 10, 14, m[Sigma[r, 4]],  m[Sigma[r, 5]]);
                G(3, 7, 11, 15, m[Sigma[r, 6]],  m[Sigma[r, 7]]);
                G(0, 5, 10, 15, m[Sigma[r, 8]],  m[Sigma[r, 9]]);
                G(1, 6, 11, 12, m[Sigma[r, 10]], m[Sigma[r, 11]]);
                G(2, 7,  8, 13, m[Sigma[r, 12]], m[Sigma[r, 13]]);
                G(3, 4,  9, 14, m[Sigma[r, 14]], m[Sigma[r, 15]]);
            }
            for (int i = 0; i < 8; i++) { h[i] ^= v[i] ^ v[i + 8]; }
        }
    }

    // Ed25519 signature verification (RFC 8032) with BigInteger arithmetic.
    // Slow but simple; verification only, so no secret-dependent timing.
    public static class Ed25519
    {
        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        private static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
        private static readonly BigInteger D = Mod(new BigInteger(-121665) * Inv(new BigInteger(121666)));
        private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
        private static readonly BigInteger[] BasePoint = MakeBasePoint();

        private static BigInteger Mod(BigInteger x)
        {
            BigInteger r = BigInteger.Remainder(x, P);
            return r.Sign < 0 ? r + P : r;
        }

        private static BigInteger Inv(BigInteger x)
        {
            return BigInteger.ModPow(Mod(x), P - 2, P);
        }

        private static BigInteger FromLE(byte[] src, int offset, int length)
        {
            byte[] t = new byte[length + 1]; // trailing zero keeps it positive
            Buffer.BlockCopy(src, offset, t, 0, length);
            return new BigInteger(t);
        }

        private static bool TryRecoverX(BigInteger y, int sign, out BigInteger x)
        {
            x = BigInteger.Zero;
            BigInteger y2 = Mod(y * y);
            BigInteger x2 = Mod((y2 - 1) * Inv(D * y2 + 1));
            if (x2.IsZero)
            {
                return sign == 0;
            }
            x = BigInteger.ModPow(x2, (P + 3) / 8, P);
            if (!Mod(x * x - x2).IsZero) { x = Mod(x * SqrtM1); }
            if (!Mod(x * x - x2).IsZero) { return false; }
            if ((x.IsEven ? 0 : 1) != sign) { x = P - x; }
            return true;
        }

        private static BigInteger[] MakeBasePoint()
        {
            BigInteger y = Mod(4 * Inv(5));
            BigInteger x;
            TryRecoverX(y, 0, out x);
            return new BigInteger[] { x, y, BigInteger.One, Mod(x * y) };
        }

        // Extended coordinates (X, Y, Z, T).
        private static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
        {
            BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
            BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
            BigInteger c = Mod(2 * p[3] * q[3] * D);
            BigInteger d = Mod(2 * p[2] * q[2]);
            BigInteger e = b - a;
            BigInteger f = d - c;
            BigInteger g = d + c;
            BigInteger hh = b + a;
            return new BigInteger[] { Mod(e * f), Mod(g * hh), Mod(f * g), Mod(e * hh) };
        }

        private static BigInteger[] ScalarMul(BigInteger s, BigInteger[] p)
        {
            BigInteger[] q = new BigInteger[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };
            while (s.Sign > 0)
            {
                if (!s.IsEven) { q = Add(q, p); }
                p = Add(p, p);
                s = s >> 1;
            }
            return q;
        }

        private static byte[] Encode(BigInteger[] p)
        {
            BigInteger zi = Inv(p[2]);
            BigInteger x = Mod(p[0] * zi);
            BigInteger y = Mod(p[1] * zi);
            byte[] raw = y.ToByteArray();
            byte[] output = new byte[32];
            Buffer.BlockCopy(raw, 0, output, 0, Math.Min(raw.Length, 32));
            if (!x.IsEven) { output[31] |= 0x80; }
            return output;
        }

        private static BigInteger[] Decode(byte[] s)
        {
            byte[] t = (byte[])s.Clone();
            int sign = (t[31] >> 7) & 1;
            t[31] &= 0x7f;
            BigInteger y = FromLE(t, 0, 32);
            if (y >= P) { return null; }
            BigInteger x;
            if (!TryRecoverX(y, sign, out x)) { return null; }
            return new BigInteger[] { x, y, BigInteger.One, Mod(x * y) };
        }

        public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32 || signature == null || signature.Length != 64) { return false; }
            BigInteger[] a = Decode(publicKey);
            if (a == null) { return false; }
            BigInteger s = FromLE(signature, 32, 32);
            if (s >= L) { return false; }
            byte[] k;
            using (SHA512 sha = SHA512.Create())
            {
                sha.TransformBlock(signature, 0, 32, null, 0);
                sha.TransformBlock(publicKey, 0, 32, null, 0);
                sha.TransformFinalBlock(message, 0, message.Length);
                k = sha.Hash;
            }
            BigInteger kk = BigInteger.Remainder(FromLE(k, 0, 64), L);
            BigInteger[] negA = new BigInteger[] { Mod(-a[0]), a[1], a[2], Mod(-a[3]) };
            // R' = [s]B - [k]A must encode to exactly the R in the signature.
            byte[] r = Encode(Add(ScalarMul(s, BasePoint), ScalarMul(kk, negA)));
            for (int i = 0; i < 32; i++)
            {
                if (r[i] != signature[i]) { return false; }
            }
            return true;
        }
    }

    public static class Verifier
    {
        private const int MaxLegacyMessage = 512 * 1024 * 1024;

        private static byte[] DecodeBase64(string s, int expectedLength, string what)
        {
            byte[] b;
            try { b = Convert.FromBase64String(s.Trim()); }
            catch (FormatException) { throw new VerificationException(what + " is not valid base64"); }
            if (b.Length != expectedLength) { throw new VerificationException(what + " has the wrong length"); }
            return b;
        }

        private static bool StartsWith(byte[] line, string prefix)
        {
            byte[] p = Encoding.ASCII.GetBytes(prefix);
            if (line.Length < p.Length) { return false; }
            for (int i = 0; i < p.Length; i++) { if (line[i] != p[i]) { return false; } }
            return true;
        }

        private static byte[][] SplitLines(byte[] data)
        {
            byte[][] lines = new byte[4][];
            int start = 0;
            for (int n = 0; n < 4; n++)
            {
                if (start > data.Length) { throw new VerificationException("signature file is truncated"); }
                int end = Array.IndexOf(data, (byte)10, start);
                if (end < 0) { end = data.Length; }
                int len = end - start;
                if (len > 0 && data[start + len - 1] == 13) { len--; }
                lines[n] = new byte[len];
                Buffer.BlockCopy(data, start, lines[n], 0, len);
                start = end + 1;
            }
            return lines;
        }

        // Verifies filePath against the minisign signature in sigPath using the
        // base64 public key. Returns the trusted comment; throws
        // VerificationException on any failure.
        public static string VerifyFile(string publicKeyBase64, string filePath, string sigPath)
        {
            byte[] pk = DecodeBase64(publicKeyBase64, 42, "public key");
            if (pk[0] != 0x45 || pk[1] != 0x64) { throw new VerificationException("unsupported public key algorithm"); }
            byte[] keyId = new byte[8];
            byte[] pub = new byte[32];
            Buffer.BlockCopy(pk, 2, keyId, 0, 8);
            Buffer.BlockCopy(pk, 10, pub, 0, 32);

            FileInfo sigInfo = new FileInfo(sigPath);
            if (!sigInfo.Exists || sigInfo.Length > 4096) { throw new VerificationException("signature file missing or too large"); }
            byte[][] lines = SplitLines(File.ReadAllBytes(sigPath));
            if (!StartsWith(lines[0], "untrusted comment: ")) { throw new VerificationException("signature file: bad untrusted comment line"); }
            byte[] sig = DecodeBase64(Encoding.ASCII.GetString(lines[1]), 74, "signature");
            const string tcPrefix = "trusted comment: ";
            if (!StartsWith(lines[2], tcPrefix)) { throw new VerificationException("signature file: bad trusted comment line"); }
            byte[] trusted = new byte[lines[2].Length - tcPrefix.Length];
            Buffer.BlockCopy(lines[2], tcPrefix.Length, trusted, 0, trusted.Length);
            byte[] globalSig = DecodeBase64(Encoding.ASCII.GetString(lines[3]), 64, "global signature");

            bool prehashed;
            if (sig[0] == 0x45 && sig[1] == 0x44) { prehashed = true; }        // "ED"
            else if (sig[0] == 0x45 && sig[1] == 0x64) { prehashed = false; }  // "Ed" (legacy)
            else { throw new VerificationException("unsupported signature algorithm"); }
            for (int i = 0; i < 8; i++)
            {
                if (sig[2 + i] != keyId[i]) { throw new VerificationException("signature was made with a different key (key id mismatch)"); }
            }
            byte[] sigBytes = new byte[64];
            Buffer.BlockCopy(sig, 10, sigBytes, 0, 64);

            byte[] message;
            if (prehashed)
            {
                using (FileStream fs = File.OpenRead(filePath)) { message = Blake2b512.HashStream(fs); }
            }
            else
            {
                if (new FileInfo(filePath).Length > MaxLegacyMessage) { throw new VerificationException("file too large for a legacy signature"); }
                message = File.ReadAllBytes(filePath);
            }
            if (!Ed25519.Verify(pub, message, sigBytes)) { throw new VerificationException("signature verification FAILED"); }

            byte[] global = new byte[64 + trusted.Length];
            Buffer.BlockCopy(sigBytes, 0, global, 0, 64);
            Buffer.BlockCopy(trusted, 0, global, 64, trusted.Length);
            if (!Ed25519.Verify(pub, global, globalSig)) { throw new VerificationException("trusted comment signature verification FAILED"); }
            return Encoding.UTF8.GetString(trusted);
        }
    }
}
'@

function Initialize-CavMinisign {
    if ('CavMinisign.Verifier' -as [type]) { return }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -TypeDefinition $CavMinisignSource -Language CSharp
    } else {
        Add-Type -TypeDefinition $CavMinisignSource -Language CSharp -ReferencedAssemblies 'System.Numerics'
    }
}

function New-CavCertificate([byte[]]$Der) {
    $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
    if ($loader) { return $loader::LoadCertificate($Der) }
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $Der)
}

function Assert-CavPublicKey {
    # The key is substituted at build time; refuse to run an unrendered script.
    if ($MinisignPublicKey -notmatch '^RW[A-Za-z0-9+/]{54}$') {
        throw 'This install script has no release public key embedded. Use the install.ps1 produced by scripts/build-dist.sh.'
    }
}

# Throws unless SignatureFile is a valid minisign signature of File by the
# embedded release key. Returns the trusted comment.
function Test-CavMinisignSignature {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$SignatureFile
    )
    Assert-CavPublicKey
    Initialize-CavMinisign
    $f = (Resolve-Path -LiteralPath $File).ProviderPath
    $s = (Resolve-Path -LiteralPath $SignatureFile).ProviderPath
    try {
        return [CavMinisign.Verifier]::VerifyFile($MinisignPublicKey, $f, $s)
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        throw ('Signature verification failed for ' + $File + ': ' + $msg)
    }
}

# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------

function Write-Step([string]$Message) { Write-Host ('==> ' + $Message) }

# Downloads Url to Path. With a callback from [CavMinisign.Tls], that callback
# alone decides whether the server certificate is trusted.
function Save-CavDownload {
    param([string]$Url, [string]$Path, [Net.Security.RemoteCertificateValidationCallback]$Validate)
    $req = [Net.HttpWebRequest][Net.WebRequest]::Create($Url)
    $req.AllowAutoRedirect = $false
    $req.Timeout = 120000
    if ($Validate) { $req.ServerCertificateValidationCallback = $Validate }
    $resp = $req.GetResponse()
    try {
        if ([int]$resp.StatusCode -ne 200) { throw ('HTTP ' + [int]$resp.StatusCode + ' for ' + $Url) }
        $in = $resp.GetResponseStream()
        $out = [IO.File]::Create($Path)
        try { $in.CopyTo($out) } finally { $out.Dispose(); $in.Dispose() }
    } finally {
        $resp.Close()
    }
}

# Returns the DER bytes of the single certificate in a PEM file.
function ConvertFrom-CavPem([string]$Path) {
    $text = [IO.File]::ReadAllText($Path)
    $m = [regex]::Matches($text, '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')
    if ($m.Count -ne 1) { throw ($Path + ' must hold exactly one PEM certificate') }
    return , [Convert]::FromBase64String(($m[0].Groups[1].Value -replace '\s', ''))
}

function ConvertTo-CavPem([byte[]]$Der) {
    return "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($Der, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
}

function Get-CavSha256Hex([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'install.ps1 must be run from an elevated (Administrator) PowerShell.'
    }
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw ($FilePath + ' ' + ($Arguments -join ' ') + ' failed with exit code ' + $LASTEXITCODE) }
}

# Reads TCPSocket/TCPAddr from %ProgramFiles%\ClamAV\clamd.conf.
function Get-ClamdAddressFromConfig {
    $conf = Join-Path $ProgramFilesDir 'ClamAV\clamd.conf'
    if (-not (Test-Path -LiteralPath $conf)) { return $null }
    $port = $null
    $addr = $null
    foreach ($line in Get-Content -LiteralPath $conf) {
        $l = $line.Trim()
        if ($l.StartsWith('#')) { continue }
        if ($l -match '^TCPSocket\s+(\d+)\s*$') { $port = $Matches[1] }
        elseif ($l -match '^TCPAddr\s+(\S+)\s*$' -and -not $addr) { $addr = $Matches[1] }
    }
    if (-not $port) { return $null }
    if (-not $addr -or $addr -eq '0.0.0.0' -or $addr -eq '::') { $addr = '127.0.0.1' }
    if ($addr -eq '::1') { $addr = '[::1]' }
    if ($addr -ne 'localhost' -and $addr -ne '[::1]' -and $addr -notmatch '^127\.\d+\.\d+\.\d+$') {
        throw ('clamd.conf sets TCPAddr ' + $addr + ', which is not loopback. The agent only talks to clamd on 127.0.0.1/::1; add "TCPAddr 127.0.0.1" or pass -ClamdAddress.')
    }
    return ('tcp://' + $addr + ':' + $port)
}

function Set-CavAcl {
    param([string]$Path, [string[]]$Grants)
    # /reset then /inheritance:r leaves exactly the grants listed here.
    Invoke-Native 'icacls.exe' @($Path, '/reset', '/Q')
    Invoke-Native 'icacls.exe' (@($Path, '/inheritance:r', '/Q', '/grant:r') + $Grants)
}

function Install-CavAgent {
    Assert-Administrator
    Assert-CavPublicKey

    if (-not $ServerUrl) { throw '-ServerUrl is required (https://...).' }
    $uri = $null
    if (-not [Uri]::TryCreate($ServerUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw '-ServerUrl must be an absolute https:// URL.'
    }
    $base = $ServerUrl.TrimEnd('/')

    $token = $EnrollToken
    if (-not $token) { $token = $env:CAV_ENROLL_TOKEN }
    $enrolled = Test-Path -LiteralPath $CredPath
    $needEnroll = $Reinstall -or -not $enrolled
    if ($needEnroll -and -not $token) {
        throw 'An enrollment token is required: pass -EnrollToken or set $env:CAV_ENROLL_TOKEN.'
    }

    $clamd = $ClamdAddress
    if (-not $clamd) { $clamd = Get-ClamdAddressFromConfig }
    if (-not $clamd) { $clamd = 'tcp://127.0.0.1:3310' }

    $caSha = $CaSha256
    if (-not $caSha) { $caSha = $env:CAV_CA_SHA256 }
    if ($caSha) {
        $caSha = ($caSha -replace ':', '').ToLowerInvariant()
        if ($caSha -notmatch '^[0-9a-f]{64}$') { throw '-CaSha256 must be a SHA-256 fingerprint (64 hex characters).' }
    }

    # PowerShell 5.1 may default to TLS 1.0.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('cav-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $caDer = $null
    $newCa = $false
    try {
        if ($caSha) {
            Write-Step 'Downloading the console CA and checking its fingerprint'
            Initialize-CavMinisign
            $caTmp = Join-Path $tmp 'console-ca.pem'
            Save-CavDownload ($base + '/downloads/console-ca.pem') $caTmp ([CavMinisign.Tls]::AcceptAny())
            $caDer = ConvertFrom-CavPem $caTmp
            $got = Get-CavSha256Hex $caDer
            if ($got -ne $caSha) { throw ('Console CA fingerprint mismatch (got ' + $got + ', expected ' + $caSha + '). NOT installing.') }
            $newCa = $true
        } elseif (-not $Reinstall -and (Test-Path -LiteralPath $CaPath)) {
            # An upgrade keeps the trust set up at enrollment. A re-enrollment
            # follows the parameters it was given (a console may have moved to
            # a public certificate).
            Write-Step ('Using the console CA installed at ' + $CaPath)
            Initialize-CavMinisign
            $caDer = ConvertFrom-CavPem $CaPath
        }

        Write-Step ('Downloading ' + $BinaryName + ' from ' + $base + '/downloads/')
        $bin = Join-Path $tmp $BinaryName
        $sig = $bin + '.minisig'
        if ($caDer) {
            $pinned = [CavMinisign.Tls]::PinnedTo((New-CavCertificate $caDer))
            Save-CavDownload ($base + '/downloads/' + $BinaryName) $bin $pinned
            Save-CavDownload ($base + '/downloads/' + $BinaryName + '.minisig') $sig $pinned
        } else {
            Invoke-WebRequest -UseBasicParsing -Uri ($base + '/downloads/' + $BinaryName) -OutFile $bin
            Invoke-WebRequest -UseBasicParsing -Uri ($base + '/downloads/' + $BinaryName + '.minisig') -OutFile $sig
        }

        Write-Step 'Verifying minisign signature'
        $tc = Test-CavMinisignSignature -File $bin -SignatureFile $sig
        Write-Host ('    signature OK; trusted comment: ' + $tc)

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') {
            Write-Step 'Stopping existing service'
            Stop-Service -Name $ServiceName -Force
            (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }

        Write-Step ('Installing ' + $ExePath)
        if (-not (Test-Path -LiteralPath $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
        Copy-Item -LiteralPath $bin -Destination $ExePath -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # The service (and so its virtual account) must exist before ACLs can
    # name NT SERVICE\ClamAVAgent.
    $imagePath = '"' + $ExePath + '" run'
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Step ('Creating service ' + $ServiceName)
        New-Service -Name $ServiceName -BinaryPathName $imagePath -DisplayName 'ClamAV Console Agent' `
            -Description 'Reports ClamAV status to the MSP console (outbound HTTPS only).' -StartupType Automatic | Out-Null
    } else {
        Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName) -Name ImagePath -Value $imagePath
    }
    Invoke-Native 'sc.exe' @('config', $ServiceName, 'obj=', $ServiceAcct, 'start=', 'auto')
    Invoke-Native 'sc.exe' @('sidtype', $ServiceName, 'unrestricted')
    # Restart on crashes. failureflag 0: a clean stop with an exit code (e.g.
    # 78 for a revoked agent) is NOT treated as a failure, so no restart.
    Invoke-Native 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/300000')
    Invoke-Native 'sc.exe' @('failureflag', $ServiceName, '0')

    Write-Step ('Securing ' + $DataDir)
    foreach ($d in @($DataDir, $LogDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    }
    # Inheritable: Administrators full, service Modify (so it can atomically
    # replace the credential). SYSTEM on the folder itself only, so new files
    # (e.g. a rotated credential) get Administrators + service only.
    Set-CavAcl $DataDir @(($SidAdmins + ':(OI)(CI)F'), ($SidSystem + ':F'), ($ServiceAcct + ':(OI)(CI)M'))
    Set-CavAcl $LogDir @(($SidAdmins + ':(OI)(CI)F'), ($SidSystem + ':(OI)(CI)F'), ($ServiceAcct + ':(OI)(CI)M'))

    if ($newCa) {
        # Written from the verified DER, so the file holds only that certificate.
        [IO.File]::WriteAllText($CaPath, (ConvertTo-CavPem $caDer), [Text.Encoding]::ASCII)
        Set-CavAcl $CaPath @(($SidAdmins + ':F'), ($SidSystem + ':F'), ($ServiceAcct + ':R'))
        Write-Step ('Installed the console CA at ' + $CaPath)
    }

    if ($needEnroll) {
        Write-Step ('Enrolling with ' + $base + ' (clamd ' + $clamd + ')')
        $enrollArgs = @('enroll', '--server', $base, '--clamd', $clamd, '--config', $ConfigPath)
        if ($Reinstall -or $enrolled) { $enrollArgs += '--replace' }
        if ($caDer) { $enrollArgs += @('--ca-cert-file', $CaPath) }
        # Token via environment, never on the command line.
        $env:CAV_ENROLL_TOKEN = $token
        try {
            & $ExePath @enrollArgs | Out-Host
            if ($LASTEXITCODE -ne 0) { throw ('Enrollment failed (exit code ' + $LASTEXITCODE + ').') }
        } finally {
            Remove-Item Env:\CAV_ENROLL_TOKEN -ErrorAction SilentlyContinue
        }
        if (-not $caDer -and (Test-Path -LiteralPath $CaPath)) {
            Remove-Item -LiteralPath $CaPath -Force
            Write-Step 'Removed the console CA from an earlier enrollment (no longer used)'
        }
    } else {
        Write-Step 'Already enrolled; keeping existing credential (use -Reinstall to re-enroll)'
        if ($caDer -and -not (Select-String -LiteralPath $ConfigPath -Pattern '^ca_cert_file:' -Quiet)) {
            Write-Warning 'The existing enrollment does not use the console CA. Run again with -Reinstall and a new token.'
        }
    }

    # Credential: service + Administrators only. Config: read-only for the service.
    Set-CavAcl $CredPath @(($SidAdmins + ':F'), ($ServiceAcct + ':M'))
    Set-CavAcl $ConfigPath @(($SidAdmins + ':F'), ($SidSystem + ':F'), ($ServiceAcct + ':R'))

    Write-Step 'Starting service'
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    $status = (Get-Service -Name $ServiceName).Status
    Write-Host ('    ' + $ServiceName + ' is ' + $status)
    if ($status -ne 'Running') {
        Write-Warning ('Service is not running. Check ' + (Join-Path $LogDir 'agent.log') + ' and the System event log.')
    }
    & $ExePath status --config $ConfigPath | Out-Host
    Write-Step 'Done'
}

if ($VerifyOnly) {
    if (-not $VerifyFile -or -not $VerifySignatureFile) { throw '-VerifyOnly needs -VerifyFile and -VerifySignatureFile.' }
    try {
        $tc = Test-CavMinisignSignature -File $VerifyFile -SignatureFile $VerifySignatureFile
        Write-Host ('Signature OK. Trusted comment: ' + $tc)
        exit 0
    } catch {
        Write-Host $_.Exception.Message
        exit 1
    }
}

Install-CavAgent
