using deferred_signing_in_pdf_file;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Syncfusion.Drawing;
using Syncfusion.Pdf.Parsing;
using Syncfusion.Pdf.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


//Register your Syncfusion License Key
Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense("Your License Key");


//Input files
string inputPdfFile = "data/credit_card_statement.pdf";
string publicCertificate = "data/public_certificate.cer";
string signatureName = "Signature";
string pfxFile = "data/PDF.pfx";
string password = "password123";
string hashAlgorithm = "SHA256";


//Prepare document and create digest to sign later.
byte[] documentHash = null;
MemoryStream documentStream = PrepareDocumentAndCreateDigest(inputPdfFile, publicCertificate, out documentHash, signatureName );

//Sign the document hash using external signer.
byte[] signedHash = SignDocument(documentHash, pfxFile, password, hashAlgorithm);

//Get the timestamp token using the signed hash.
byte[] timestampToken = GetRFC3161TimeStampToken(signedHash);

//Deferred signing
MemoryStream outputFileStream = DeferredSigning(documentStream, signedHash, timestampToken, hashAlgorithm, publicCertificate, signatureName);

//Save the signed document to disk.
using (FileStream fileStream = new FileStream("Signed Document.pdf", FileMode.Create, FileAccess.ReadWrite))
{
    outputFileStream.WriteTo(fileStream);
}

//Enable long term validity.
CreateLongTermValidity(outputFileStream, signatureName);

//Dispose the streams
documentStream.Close();
outputFileStream.Close();



MemoryStream PrepareDocumentAndCreateDigest(string inputPdfFile, string publicCertificate, out byte[] documentHash, string signatureName)
{
    //Load the input file to sign.
    FileStream documentStream = new FileStream(inputPdfFile, FileMode.Open, FileAccess.Read);

    //Load an existing PDF document.
    PdfLoadedDocument loadedDocument = new PdfLoadedDocument(documentStream);

    //Creates a PDF signature and pass the PdfCertificate as null.
    PdfSignature signature = new PdfSignature(loadedDocument, loadedDocument.Pages[0], null, signatureName);

    //Sets the signature information.
    signature.Bounds = new RectangleF(new PointF(0, 0), new SizeF(100, 30));
    signature.Settings.CryptographicStandard = CryptographicStandard.CADES;
    signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;

    //Create a empty external signer to get the document hash.
    SignEmpty emptyExternalSigner = new SignEmpty("SHA256");

    //Add public certificates.
    List<X509Certificate2> certificates = new List<X509Certificate2>();
    certificates.Add(new X509Certificate2(publicCertificate));

    //Add the external signer to the signature.
    signature.AddExternalSigner(emptyExternalSigner, certificates, null);

    //Save the document.
    MemoryStream stream = new MemoryStream();
    loadedDocument.Save(stream);
    //Close the PDF document.
    loadedDocument.Close(true);

    //Get the document hash.
    documentHash = emptyExternalSigner.dataToSign;

    return stream;
}

MemoryStream DeferredSigning(MemoryStream inputFile, byte[] signedHash, byte[] timestampToken, string hashAlgorithm, string publicCertificate, string signatureName)
{
    //Create a external signer to sign the document hash.
    ExternalSigner externalSigner = new ExternalSigner(hashAlgorithm, signedHash, timestampToken);

    //Add public certificates.
    List<X509Certificate2> certificates = new List<X509Certificate2>();
    certificates.Add(new X509Certificate2(publicCertificate));

    MemoryStream outputFileStream = new MemoryStream();

    //Replace the empty signature.
    PdfSignature.ReplaceEmptySignature(inputFile, string.Empty, outputFileStream, signatureName, externalSigner, certificates);

    return outputFileStream;
}

void CreateLongTermValidity(MemoryStream inputFile, string SignatureName)
{
    //Load the signed PDF document
    PdfLoadedDocument document = new PdfLoadedDocument(inputFile);

    //Get the signature field
    PdfLoadedField loadedField = null;
    document.Form.Fields.TryGetField(SignatureName, out loadedField);

    if (loadedField != null && loadedField is PdfLoadedSignatureField)
    {
        PdfLoadedSignatureField loadedSignatureField = (PdfLoadedSignatureField)loadedField;

        //Create the long term validity.
        loadedSignatureField.Signature.EnableLtv = true;
    }

    //Save the signed document to disk.
    using (FileStream fileStream = new FileStream("Signed Document with LTV.pdf", FileMode.Create, FileAccess.ReadWrite))
    {
        document.Save(fileStream);
    }

    //Dispose the document
    document.Close(true);
}


//Sign the document hash using external signer. In this example, we are using the RSACryptoServiceProvider to sign the document hash for the demonstration purpose.
byte[] SignDocument(byte[] documentHash, string privateKeyPath, string password, string hashAlgorithm)
{
    //Load the pfx file to sign the document hash.
    X509Certificate2 digitalID = new X509Certificate2(privateKeyPath, password);

    if (digitalID != null && digitalID.HasPrivateKey)
    {
        var rsaPrivateKey = digitalID.GetRSAPrivateKey();
        if (rsaPrivateKey != null)
        {
            if (rsaPrivateKey is RSACryptoServiceProvider)
            {
                RSACryptoServiceProvider rsa = rsaPrivateKey as RSACryptoServiceProvider;
                return rsa.SignData(documentHash, hashAlgorithm);
            }
            else if (rsaPrivateKey is RSACng)
            {
                RSACng rsa = rsaPrivateKey as RSACng;
                return rsa.SignData(documentHash, GetHashAlgorithm(hashAlgorithm), RSASignaturePadding.Pkcs1);
            }
            else if (rsaPrivateKey is System.Security.Cryptography.RSAOpenSsl)
            {
                RSAOpenSsl rsa = rsaPrivateKey as RSAOpenSsl;
                return rsa.SignData(documentHash, GetHashAlgorithm(hashAlgorithm), RSASignaturePadding.Pkcs1);
            }
        }
        else
        {
            throw new Exception("The certificate does not have a private key.");
        }
    }
    return null;
}

HashAlgorithmName GetHashAlgorithm(string hashAlgorithm)
{
    switch (hashAlgorithm)
    {
        case "SHA1":
            return HashAlgorithmName.SHA1;
        case "SHA256":
            return HashAlgorithmName.SHA256;
        case "SHA384":
            return HashAlgorithmName.SHA384;
        case "SHA512":
            return HashAlgorithmName.SHA512;
        default:
            throw new Exception("Invalid hash algorithm.");
    }
}

// Generate the RFC3161 timestamp token using the provided signed data.
// Note this method is implemented with the help of BouncyCastle library.
// You can replace this method based on your third party service provider.
byte[] GetRFC3161TimeStampToken(byte[] bytes)
{
    SHA256 sha256 = SHA256.Create();
    byte[] hash = sha256.ComputeHash(bytes);

    // Create a timestamp request using the SHA1 hash.
    TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
    reqGen.SetCertReq(true);
    TimeStampRequest tsReq = reqGen.Generate(TspAlgorithms.Sha256, hash, BigInteger.ValueOf(100));
    byte[] tsData = tsReq.GetEncoded();

    // Use HttpClient instead of HttpWebRequest.
    using (HttpClient client = new HttpClient())
    {
        //client.DefaultRequestHeaders.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes("9024:yourPass")));
        HttpContent content = new ByteArrayContent(tsData);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response = client.PostAsync("https://rfc3161.ai.moda", content).Result; //Use your timestamp address

        if (response.IsSuccessStatusCode)
        {
            byte[] responseBytes = response.Content.ReadAsByteArrayAsync().Result;
            TimeStampResponse tsRes = new TimeStampResponse(responseBytes);
            return tsRes.TimeStampToken.GetEncoded();
        }
    }

    return null;
}




