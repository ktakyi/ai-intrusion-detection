"""
AI-assisted intrusion monitoring tool.

This script monitors OpenCanary JSON logs, extracts suspicious event
information, enriches source IP addresses with location data, and sends
the event details to a locally running Ollama model for analysis.

For educational and authorized defensive security testing only.
"""
import ipaddress
import json
import os
import time
import ollama
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


LOG_FILE_PATH = "/var/tmp/opencanary.log"
OLLAMA_MODEL = "llama3.2:1b"


def get_location(ip_address: str) -> str:
    """Look up an approximate location for a public IP address."""

    try:
        parsed_ip = ipaddress.ip_address(ip_address)

        if (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_reserved
        ):
            return "Local/Private Network"

        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            headers={"User-Agent": "OpenCanary-AI-IDS-Lab/1.0"},
            timeout=10,
        )
        response.raise_for_status()

        data = response.json()

        city = data.get("city") or "Unknown City"
        region = data.get("region") or "Unknown Region"
        country = data.get("country_name") or "Unknown Country"

        return f"{city}, {region}, {country}"

    except (ValueError, requests.RequestException, json.JSONDecodeError):
        return "Location Lookup Unavailable"


def analyze_incident(ip_address: str, raw_log: str) -> None:
    """Send the event to the local Llama model for classification."""

    location_string = get_location(ip_address)

    prompt = f"""
You are an automated Security Operations Center analyst.

Analyze the OpenCanary honeypot event below.

Instructions:
1. Classify the event as LOW, MEDIUM, or HIGH severity.
2. Give a one-sentence technical explanation.
3. Base the assessment only on evidence present in the log.
4. Do not invent attacker intent or capabilities.

Source IP: {ip_address}
Approximate GeoIP location: {location_string}
Raw OpenCanary log: {raw_log}
"""

    try:
        ai_response = ollama.generate(
            model=OLLAMA_MODEL,
            prompt=prompt,
        )
        ai_analysis = ai_response["response"].strip()

    except Exception as error:
        ai_analysis = f"AI Analysis Engine Offline: {error}"

    print("\n" + "=" * 70)
    print("NEW INTRUSION DETECTED BY AI IDS")
    print(f"Attacker/Source IP: {ip_address}")
    print(f"Approximate Location: {location_string}")
    print("AI Analysis:")
    print(ai_analysis)
    print("=" * 70 + "\n")


class LogFileHandler(FileSystemEventHandler):
    def __init__(self) -> None:
        self.file = open(LOG_FILE_PATH, "r", encoding="utf-8")
        self.file.seek(0, os.SEEK_END)

    def on_modified(self, event) -> None:
        if os.path.abspath(event.src_path) != os.path.abspath(LOG_FILE_PATH):
            return

        for line in self.file.readlines():
            line = line.strip()

            if not line:
                continue

            try:
                log_data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip_address = str(log_data.get("src_host", "")).strip()

            if ip_address:
                analyze_incident(ip_address, line)


def main() -> None:
    if not os.path.exists(LOG_FILE_PATH):
        raise FileNotFoundError(
            f"{LOG_FILE_PATH} does not exist. Start OpenCanary first."
        )

    print("AI-Driven IDS Monitoring Dashboard Active")
    print(f"Watching log: {LOG_FILE_PATH}")
    print(f"Local AI model: {OLLAMA_MODEL}")
    print("Press Ctrl+C to stop.\n")

    event_handler = LogFileHandler()
    observer = Observer()
    observer.schedule(
        event_handler,
        path=os.path.dirname(LOG_FILE_PATH),
        recursive=False,
    )
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
