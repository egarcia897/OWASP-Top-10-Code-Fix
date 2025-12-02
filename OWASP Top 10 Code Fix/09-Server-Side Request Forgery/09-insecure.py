"""#09 Server-Side Request Forgery
- Insecure code python"""

url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
