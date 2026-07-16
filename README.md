# AI-Powered Intrusion Detection System

## Overview

This project is an AI-assisted intrusion monitoring system created in a Kali Linux environment. It uses OpenCanary to detect suspicious network activity and login attempts. A Python monitoring script reads OpenCanary log events, gathers available geographic information about the source IP address, and sends the event details to a locally running Ollama language model for analysis.

The system produces a readable incident assessment that can help a security analyst understand the event, its possible severity, and recommended response actions.

> This project was created for educational and defensive cybersecurity purposes in an authorized lab environment.

## Project Objectives

- Monitor OpenCanary security logs in real time
- Detect new suspicious login and connection events
- Extract useful information from JSON log entries
- Enrich events with IP geolocation information
- Use a locally running AI model to analyze incidents
- Produce readable incident summaries and response recommendations

## Technologies Used

- Python
- Kali Linux
- OpenCanary
- Ollama
- Watchdog
- Requests
- JSON
- IP geolocation API
- Linux log monitoring

## System Workflow

1. OpenCanary monitors configured network services.
2. A connection or login attempt generates a JSON log entry.
3. Python's Watchdog library detects the change to the log file.
4. The script reads and parses the new event.
5. The source IP address is sent to a geolocation service.
6. The event and location information are passed to Ollama.
7. The AI model generates an incident assessment.
8. The assessment is displayed for review.

## Architecture

## Screenshots

### OpenCanary Monitoring Service

![OpenCanary running in Kali Linux](sample-data/screenshots/opencanary-running.png)

### Simulated Intrusion Event

![Simulated intrusion event captured by OpenCanary](sample-data/screenshots/intrusion-event.png)

### AI-Generated Incident Analysis

![AI-generated incident assessment](sample-data/screenshots/ai-analysis.png)

### Email Notification
![Email notification of intrusion](sample-data/screenshots/Email-intrusion-noti.png)

```text
Potential Intruder
        |
        v
OpenCanary Honeypot
        |
        v
JSON Security Log
        |
        v
Python Log Monitor
        |
        +----> IP Geolocation Service
        |
        v
Local Ollama AI Model
        |
        v
Incident Summary and Response Recommendations
