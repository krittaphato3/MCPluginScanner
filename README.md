# MCPluginScanner (DarkSearch Ultra V5 Beta)

A high-performance, multi-threaded Minecraft server scanner and plugin detector built with Python and CustomTkinter. This tool allows you to fetch server IPs from popular server lists or scan IP ranges to detect specific plugins (e.g., Vulcan, Spartan, AAC).

## ⚡ Features

* **Multi-Source Fetching:** Scrape IPs automatically from:
    * MinecraftServers.org
    * Minecraft-MP.com
    * TopG.org
    * Minecraft-Server-List.com
* **IP Range Scanning:** Support for CIDR notation (e.g., `192.168.1.0/24`).
* **Resume Capability:** stop a scan and resume exactly where you left off using **File Mode**.
* **Smart Detection:**
    * **Strict Mode:** Only saves servers containing specific plugins you defined.
    * **Loose Mode:** Saves any server with plugins, labeling them "Random/Other".
* **High Performance:** Supports up to 500 concurrent threads.
* **Real-Time Statistics:** View live counters for fetched IPs, scanned servers, hits, and errors.
* **QOL Features:**
    * Fast Knock (skips offline servers instantly).
    * Duplicate removal.
    * Summary report upon completion.
    * Dark Mode GUI.

## 🛠️ Installation

1.  **Install Python:** Ensure you have Python 3.8+ installed.
2.  **Install Dependencies:**
    Open your terminal/command prompt and run:
    ```bash
    pip install customtkinter requests mcstatus
    ```

## 🚀 Usage

1.  Run the script:
    ```bash
    python DarkSearch.py
    ```
    *(Note: Replace `DarkSearch.py` with whatever you named the script file).*

2.  **Select a Mode:**
    * **Web Scraper:** Choose a website to fetch IPs from. Click **Start** to fetch, then click **Stop Fetch & Scan** to begin checking plugins.
    * **IP Range:** Enter a range (e.g., `1.1.1.0/24`) to scan directly.
    * **Custom List:** Load your own `.txt` file of IPs.

3.  **Configure Targets:**
    * Edit the "Rules & Targets" box to include plugins you want to find (comma-separated).
    * Example: `Vulcan, Spartan, Matrix`

## 📂 Output Files

* `matches.txt`: Contains successful hits with the server IP and plugin list.
* `scanned.txt`: A history of all IPs scanned to prevent duplicates (unless "Rescan All" is enabled).
* `ips_<source>.txt`: Raw IPs fetched from websites.
* `debug.log`: Application logs for troubleshooting.

## ⚠️ Disclaimer

This tool is for **educational purposes and legitimate server administration only**. Scanning networks you do not own or have permission to test may violate terms of service or local laws. The developer assumes no responsibility for misuse.