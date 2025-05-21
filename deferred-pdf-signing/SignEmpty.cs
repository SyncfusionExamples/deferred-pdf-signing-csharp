using Syncfusion.Pdf.Security;


namespace deferred_signing_in_pdf_file
{
    public class SignEmpty : IPdfExternalSigner
    {
        private string _hashAlgorithm = "SHA1";
        public string HashAlgorithm
        {
            get { return _hashAlgorithm; }
        }

        public byte[] dataToSign = null;

        public SignEmpty(string hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm;
        }

        public byte[] Sign(byte[] message, out byte[] timeStampResponse)
        {
            //The document digest to sign later.
            dataToSign = message;

            //Set the timestamp response as null.
            timeStampResponse = null;

            //Return the signed data as null.
            return null;
        }
    }
}
