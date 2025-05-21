using Syncfusion.Pdf.Security;


namespace deferred_signing_in_pdf_file
{
    class ExternalSigner : IPdfExternalSigner
    {
        public string HashAlgorithm { get; set; }
        private byte[] _signedHash;
        private byte[]? _timestampResposne;

        public ExternalSigner(string hashAlgorithm, byte[] signedHash, byte[]? timestamp = null)
        {
            HashAlgorithm = hashAlgorithm;
            _signedHash = signedHash;
            _timestampResposne = timestamp;
        }

        public byte[] Sign(byte[] message, out byte[] timeStampResponse)
        {
            //Create a timestamp response.        
            timeStampResponse = _timestampResposne;

            //Send the signed hash.
            return _signedHash;
        }
    }
}
