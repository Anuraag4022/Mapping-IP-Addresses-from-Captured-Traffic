import pyshark
import requests
import folium


def extract_ips_from_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    ip_addresses = set()
    
    for packet in capture:
        try:
            if 'IP' in packet:
                ip_addresses.add(packet.ip.dst)  # Destination IPs
        except AttributeError:
            pass  # Ignore packets without IP layers

    capture.close()  # Ensure the capture file is closed
    return list(ip_addresses)


def get_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)  # Set a timeout for the request
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
        else:
            print(f"Failed to fetch geolocation for IP {ip}: HTTP {response.status_code}")
    except requests.RequestException as e:
        print(f"Error fetching geolocation for IP {ip}: {e}")
    return None


def plot_locations(locations, output_file="map.html"):
    if not locations:
        print("No locations to plot.")
        return

    # Create a map centered at an approximate location
    map_center = [20, 0]  # Centered at the equator
    m = folium.Map(location=map_center, zoom_start=2)
    
    for loc in locations:
        if loc["lat"] is not None and loc["lon"] is not None:
            folium.Marker(
                [loc["lat"], loc["lon"]],
                popup=f"{loc['ip']} - {loc['city']}, {loc['country']}",
            ).add_to(m)
   
    # Save map to an HTML file
    m.save(output_file)
    print(f"Map saved to {output_file}")


# Main execution flow
if __name__ == "__main__":
    # Replace with your PCAP file path
    pcap_file = "C:\\Users\\dell\\Desktop\\Cyber Security Project\\traffic.pcap"
    
    ip_list = extract_ips_from_pcap(pcap_file)
    print(f"Extracted IP addresses: {ip_list}")
    
    # Get geolocations for IPs
    locations = []
    for ip in ip_list:
        geo = get_geolocation(ip)
        if geo:
            locations.append(geo)
    
    print("Geolocated data:")
    for loc in locations:
        print(loc)
    
    # Plot locations on the map
    plot_locations(locations)
