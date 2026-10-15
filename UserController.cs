using System;

public class UserController
{
    // HATA 1: Şifre kodun içine açıkça yazılmış
    private string dbPassword = "SuperSecretPassword123!";

    public void GetUser(string userId)
    {
        // HATA 2: SQL Injection açığı
        string query = "SELECT * FROM Users WHERE Id = " + userId;
        Console.WriteLine("Sorgu çalıştırılıyor: " + query);

        // HATA 3: Null kontrolü yok
        string name = null;
        Console.WriteLine(name.ToUpper());
    }
}
