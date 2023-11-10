namespace Test
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using AWSSignatureGenerator;
    using GetSomeInput;

    public static class Program
    {
        static bool _RunForever = true;

        static string _Timestamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
        static string _HttpMethod = "GET";
        static string _Hostname = "localhost";
        static int _Port = 8000;
        static bool _Ssl = false;
        static string _FullUrl = (_Ssl ? "https://" : "http://") + _Hostname + ":" + _Port + "/";
        static NameValueCollection _Headers = null;
        static string _AccessKey = "AKIAIOSFODNN7EXAMPLE";
        static string _SecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        static string _Region = "us-west-1";
        static string _Service = "s3";

        public static void Main(string[] args)
        {
            while (_RunForever)
            {
                string userInput = Inputty.GetString("Command [?/help]:", null, false);

                switch (userInput)
                {
                    case "q":
                        _RunForever = false;
                        break;
                    case "?":
                        Menu();
                        break;
                    case "cls":
                        Console.Clear();
                        break;
                    case "v4":
                        GenerateV4Signature();
                        break;
                }
            }
        }

        static void Menu()
        {
            Console.WriteLine("");
            Console.WriteLine("Available commands:");
            Console.WriteLine("  q           Quit");
            Console.WriteLine("  ?           Help, this menu");
            Console.WriteLine("  cls         Clear the screen");
            Console.WriteLine("  v4          Generate a signature");
            Console.WriteLine("");
        }

        static void GenerateV4Signature()
        {
            Console.WriteLine("");
            _Timestamp =            Inputty.GetString("Timestamp    :", DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ"), false);
            _HttpMethod =           Inputty.GetString("HTTP method  :", _HttpMethod, false);
            _FullUrl =              Inputty.GetString("Full URL     :", _FullUrl, false);
            
            Console.WriteLine("");
            Console.WriteLine("Building headers (ENTER on key to end)");
            _Headers = Inputty.GetNameValueCollection("Key   :", "Value :", true);

            Console.WriteLine("");
            _AccessKey =            Inputty.GetString("Access key   :", _AccessKey, false);
            _SecretKey =            Inputty.GetString("Secret key   :", _SecretKey, false);
            _Region =               Inputty.GetString("Region       :", _Region, false);
            _Service =              Inputty.GetString("Service      :", _Service, false);
            string body =           Inputty.GetString("Request body :", null, true);

            if (!_Headers.AllKeys.Contains("host"))
                _Headers.Add("host", _Hostname + ":" + _Port.ToString());

            if (!String.IsNullOrEmpty(body))
            {
                if (!_Headers.AllKeys.Contains("x-amz-content-sha256"))
                {
                    string hash = Convert.ToHexString(Sha256(Encoding.UTF8.GetBytes(body))).ToLower();
                    _Headers.Add("x-amz-content-sha256", hash);
                }
            }
            else
            {
                if (!_Headers.AllKeys.Contains("x-amz-content-sha256"))
                {
                    _Headers.Add("x-amz-content-sha256", Convert.ToHexString(Sha256(Array.Empty<byte>())).ToLower());
                }
            }

            if (!_Headers.AllKeys.Contains("x-amz-date"))
                _Headers.Add("x-amz-date", _Timestamp);
             
            Console.WriteLine("");
            V4SignatureResult result = new V4SignatureResult(
                _Timestamp,
                _HttpMethod,
                _FullUrl,
                _AccessKey,
                _SecretKey,
                _Region,
                _Service,
                _Headers,
                body,
                V4PayloadHashEnum.Signed);

            Console.WriteLine(result.ToString());
        }

        private static byte[] Sha256(byte[] bytes)
        {
            if (bytes == null) return null;

            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
        }

    }
}