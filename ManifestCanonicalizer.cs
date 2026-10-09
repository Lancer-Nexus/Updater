using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace LancerNexus.Updater;

/// <summary>RFC 8785 canonicalization for the integer-valued UpdateManifest JSON schema.</summary>
public static class ManifestCanonicalizer
{
    private static readonly BigInteger MaxSafeInteger = new(9_007_199_254_740_991L);
    private static readonly BigInteger MinSafeInteger = -MaxSafeInteger;

    public static byte[] Canonicalize(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        using var output = new MemoryStream(json.Length);
        try
        {
            WriteElement(output, document.RootElement);
        }
        catch (InvalidOperationException error)
        {
            throw new InvalidDataException("Manifest-JSON enthält ungültiges Unicode.", error);
        }
        return output.ToArray();
    }

    public static byte[] Serialize(UpdateManifest manifest) =>
        Canonicalize(JsonSerializer.SerializeToUtf8Bytes(manifest, TrustRoot.JsonOptions));

    private static void WriteElement(Stream output, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                {
                    var properties = element.EnumerateObject().ToArray();
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in properties)
                        if (!names.Add(property.Name))
                            throw new InvalidDataException("Manifest JSON enthält doppelte Eigenschaftsnamen.");
                    Array.Sort(properties, static (left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));
                    WriteAscii(output, "{");
                    for (var i = 0; i < properties.Length; i++)
                    {
                        if (i != 0) WriteAscii(output, ",");
                        WriteString(output, properties[i].Name);
                        WriteAscii(output, ":");
                        WriteElement(output, properties[i].Value);
                    }
                    WriteAscii(output, "}");
                    break;
                }
            case JsonValueKind.Array:
                WriteAscii(output, "[");
                var first = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!first) WriteAscii(output, ",");
                    first = false;
                    WriteElement(output, item);
                }
                WriteAscii(output, "]");
                break;
            case JsonValueKind.String:
                WriteString(output, element.GetString() ?? throw new InvalidDataException("Null JSON string."));
                break;
            case JsonValueKind.Number:
                WriteInteger(output, element.GetRawText());
                break;
            case JsonValueKind.True:
                WriteAscii(output, "true");
                break;
            case JsonValueKind.False:
                WriteAscii(output, "false");
                break;
            case JsonValueKind.Null:
                WriteAscii(output, "null");
                break;
            default:
                throw new InvalidDataException("Manifest JSON enthält einen ungültigen Wert.");
        }
    }

    private static void WriteInteger(Stream output, string value)
    {
        if (value.Contains('.') || value.Contains('e') || value.Contains('E') ||
            !BigInteger.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var integer) ||
            integer < MinSafeInteger || integer > MaxSafeInteger)
            throw new InvalidDataException("Manifest-Zahlen müssen sichere JSON-Ganzzahlen sein.");
        WriteAscii(output, integer.ToString(CultureInfo.InvariantCulture));
    }

    private static void WriteString(Stream output, string value)
    {
        WriteAscii(output, "\"");
        Span<byte> encoded = stackalloc byte[4];
        for (var i = 0; i < value.Length;)
        {
            var status = Rune.DecodeFromUtf16(value.AsSpan(i), out var rune, out var consumed);
            if (status != System.Buffers.OperationStatus.Done)
                throw new InvalidDataException("Manifest-String enthält ungültiges Unicode.");
            i += consumed;
            switch (rune.Value)
            {
                case '"': WriteAscii(output, "\\\""); break;
                case '\\': WriteAscii(output, "\\\\"); break;
                case '\b': WriteAscii(output, "\\b"); break;
                case '\t': WriteAscii(output, "\\t"); break;
                case '\n': WriteAscii(output, "\\n"); break;
                case '\f': WriteAscii(output, "\\f"); break;
                case '\r': WriteAscii(output, "\\r"); break;
                default:
                    if (rune.Value < 0x20)
                        WriteAscii(output, "\\u00" + rune.Value.ToString("x2", CultureInfo.InvariantCulture));
                    else
                    {
                        var length = rune.EncodeToUtf8(encoded);
                        output.Write(encoded[..length]);
                    }
                    break;
            }
        }
        WriteAscii(output, "\"");
    }

    private static void WriteAscii(Stream output, string value) =>
        output.Write(Encoding.ASCII.GetBytes(value));
}
