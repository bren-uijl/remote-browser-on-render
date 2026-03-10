from app import app

# Use Flask's test client to fetch a URL
with app.test_client() as client:
    response = client.get('/fetch?url=https://example.com')
    print('Status code:', response.status_code)
    print('Content-Type:', response.content_type)
    # Print first 200 characters of the response data for verification
    data = response.data[:200]
    print('Data snippet:', data.decode('utf-8', errors='replace'))
