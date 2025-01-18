🚀Project: Mapping IP Addresses from Captured Traffic🚀

Overview:
This project leverages Python and Wireshark to analyze network traffic captured from a laptop browser. It extracts IP addresses, determines their geolocations, and visualizes them on an interactive map. The workflow uses the following technologies and libraries:

- Wireshark: To capture network traffic.
- Python: To process the captured traffic and perform geolocation lookups.
- Libraries used: `pyshark`, `requests`, and `folium`.
- Folium: For interactive map generation.

Features

1. Capture network traffic using Wireshark.
2. Extract destination IP addresses from the PCAP file. In my case it is "traffic.pcap"
3. Use the `ip-api.com` service to fetch geolocation data for each IP address.
4. Visualize the locations of the IP addresses on an interactive map.

Requirements

To run this project, ensure you have the following installed:

1. Python 3.7 or later
2. Required Python libraries:
   ```bash
   pip install pyshark requests folium
   ```
3. Wireshark for capturing traffic.

Setup and Execution

Step 1: Capture Traffic with Wireshark

1. Open Wireshark and start capturing traffic on your laptop's active network interface.
2. Browse different websites to generate traffic.
3. Stop the capture and save the file as a PCAP file (e.g., `traffic.pcap`).

Step 2: Run the Python Script

Using the Command Line

1. Place the PCAP file in your project directory.
2. Update the script's `pcap_file` variable with the path to your PCAP file.
3. Execute the script:
   ```bash
   traffic.py
   ```

Using VS Code

1. Open Visual Studio Code (VS Code).
2. Open the folder containing your script and PCAP file in VS Code.
3. Update the script's `pcap_file` variable with the path to your PCAP file.
4. In VS Code, open the script file (`script.py`).
5. Ensure you have the Python extension installed in VS Code.
6. Click the "Run" button at the top right of the editor or press `F5` to execute the script.
7. View the output in the integrated terminal.

 Step 3: View the Map

After execution, the script generates an HTML file (`map.html`) containing the interactive map. Open this file in your browser to explore the IP geolocations.

 Code Explanation

 Extracting IP Addresses

The `extract_ips_from_pcap` function uses `pyshark` to parse the PCAP file and collect unique destination IP addresses:

```python
def extract_ips_from_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    ip_addresses = set()
    for packet in capture:
        try:
            if 'IP' in packet:
                ip_addresses.add(packet.ip.dst)
        except AttributeError:
            pass
    capture.close()
    return list(ip_addresses)
```

Geolocation Lookup

The `get_geolocation` function queries `ip-api.com` to fetch geolocation data for a given IP address:

```python
def get_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "city": data.get("city"),
                    "country": data.get("country"),
                }
    except requests.RequestException as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")
    return None
```

Plotting Locations

The `plot_locations` function generates an interactive map using `folium`:

```python
def plot_locations(locations, output_file="map.html"):
    map_center = [20, 0]  # Approximate center of the world
    m = folium.Map(location=map_center, zoom_start=2)
    for loc in locations:
        if loc["lat"] is not None and loc["lon"] is not None:
            folium.Marker(
                [loc["lat"], loc["lon"]],
                popup=f"{loc['ip']} - {loc['city']}, {loc['country']}",
            ).add_to(m)
    m.save(output_file)
```

Example Output

1. **Extracted IP Addresses:

   ```
   Extracted IP addresses: ['93.184.216.34', '151.101.65.69']
   ```

2. **Geolocated Data:

   ```
   Geolocated data:
   {'ip': '93.184.216.34', 'lat': 37.4056, 'lon': -122.0775, 'city': 'Mountain View', 'country': 'United States'}
   {'ip': '151.101.65.69', 'lat': 40.7128, 'lon': -74.006, 'city': 'New York', 'country': 'United States'}
   ```

3. Generated Map:
   Open `map.html` to view markers representing the IP locations.

Notes

- Privacy**: This project uses public IP addresses only. No personal data is extracted.
- Rate Limiting**: The `ip-api.com` service allows 45 requests per minute for free usage.
- Error Handling**: The script handles cases where geolocation data is unavailable.

Future Enhancements

1. Add support for visualizing routes between IPs.
2. Integrate with advanced geolocation APIs like MaxMind for improved accuracy.
3. Provide additional analysis of the captured traffic (e.g., protocols, data sizes).

---

Feel free to customize and expand this project based on your needs!

