#nullable enable
using System;
using System.Security.Cryptography;
using System.Text;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Deterministic Idempotency-Key values for ingest submissions.
    /// </summary>
    /// <remarks>
    /// The API stores usage rows with an accumulate-on-conflict upsert, so a
    /// retry after a timeout that the server actually processed double-counts
    /// everything in the payload. The server dedups on the Idempotency-Key
    /// header; the key must therefore be identical across retries of one
    /// collection and different across collections. A UUIDv5 of
    /// (serial, module, collectedAt) has exactly that shape, and both clients
    /// derive it the same way: RFC 4122 URL namespace, name
    /// "reportmate:{serial}:{module}:{collectedAt:yyyy-MM-ddTHH:mm:ssZ}".
    /// </remarks>
    public static class IdempotencyKey
    {
        // RFC 4122 name-based namespace for URLs, big-endian.
        private static readonly byte[] UrlNamespace =
        {
            0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
            0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
        };

        public static string Create(string serialNumber, string module, DateTime collectedAt)
        {
            var stamp = collectedAt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
            var name = $"reportmate:{serialNumber}:{module}:{stamp}";
            return Uuid5(UrlNamespace, name);
        }

        private static string Uuid5(byte[] namespaceBytes, string name)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            var input = new byte[namespaceBytes.Length + nameBytes.Length];
            Buffer.BlockCopy(namespaceBytes, 0, input, 0, namespaceBytes.Length);
            Buffer.BlockCopy(nameBytes, 0, input, namespaceBytes.Length, nameBytes.Length);

            var hash = SHA1.HashData(input);

            var uuid = new byte[16];
            Buffer.BlockCopy(hash, 0, uuid, 0, 16);
            uuid[6] = (byte)((uuid[6] & 0x0F) | 0x50); // version 5
            uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80); // RFC 4122 variant

            return $"{uuid[0]:x2}{uuid[1]:x2}{uuid[2]:x2}{uuid[3]:x2}-" +
                   $"{uuid[4]:x2}{uuid[5]:x2}-{uuid[6]:x2}{uuid[7]:x2}-" +
                   $"{uuid[8]:x2}{uuid[9]:x2}-" +
                   $"{uuid[10]:x2}{uuid[11]:x2}{uuid[12]:x2}{uuid[13]:x2}{uuid[14]:x2}{uuid[15]:x2}";
        }
    }
}
