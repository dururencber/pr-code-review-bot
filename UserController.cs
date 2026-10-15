using System;
using System.IO;
using System.Net.Http;

public class UserController
{
    // Eski Tuzak 1: Şifre kodun içinde
    private string dbPassword = "SuperSecretPassword123!";
    
    // YENİ TUZAK 1: Thread-unsafe statik değişken (Race Condition)
    public static int TotalRequests = 0;

    public void GetUser(string userId)
    {
        TotalRequests++; // Thread-safe değil

        // Eski Tuzak 2: SQL Injection
        string query = "SELECT * FROM Users WHERE Id = " + userId;
        Console.WriteLine("Sorgu çalıştırılıyor: " + query);

        // Eski Tuzak 3: Null kontrolü yok
        string name = null;
        Console.WriteLine(name.ToUpper());
    }

    // YENİ TUZAK 2: Socket / Memory Leak (Her çağrıda new HttpClient)
    public void CallExternalService()
    {
        var client = new HttpClient();
        var response = client.GetStringAsync("https://api.example.com/data").Result; // .Result dead-lock riski
        Console.WriteLine(response);
    }

    // YENİ TUZAK 3: Path Traversal (Yetkisiz dosya okuma açığı)
    public string ReadUserFile(string filename)
    {
        string path = "/var/data/" + filename; // Kullanıcı ../../ yazarak sistem dosyalarını okuyabilir
        return File.ReadAllText(path);
    }

    // YENİ TUZAK 4: Empty Catch Block (Hatayı yutma anti-pattern'i)
    public void ProcessTransaction()
    {
        try
        {
            throw new InvalidOperationException("İşlem başarısız!");
        }
        catch (Exception)
        {
            // Hata yutuldu, loglanmadı!
        }
    }
}
