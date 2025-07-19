using System.Net.Http;

public class CVEChecker
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public CVEChecker(string apiKey)
    {
        _httpClient = new HttpClient();
        _apiKey = apiKey;
    }

    public async Task<string?> GetCVEsAsync(string keyword)
    {
        string encodedKeyword = Uri.EscapeDataString(keyword);
        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encodedKeyword}&resultsPerPage=3";

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("apiKey", _apiKey);

        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                Console.WriteLine($"[HATA] API Hatası - Kod: {response.StatusCode} - {keyword}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HATA] API isteği sırasında istisna oluştu: {ex.Message}");
        }

        return null;
    }
}
