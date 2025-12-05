print('test data') 
import requests

def get_vt_score(domain):
    api_key = 'YOUR_API_KEY'  # Replace with your actual VirusTotal API key
    url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        score = data['data'][0]['attributes']['last_analysis_results']['virustotal']['result']
        return score
    else:
        print(f"Error fetching VirusTotal score for {domain}: {response.text}")
        return None

# Example usage
domain = 'example.com'
score = get_vt_score(domain)
print(f"VirusTotal score for {domain}: {score}")