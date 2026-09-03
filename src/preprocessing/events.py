events = [

    {
        "type": "port_scan",
        "source": "server_01",
        "timestamp": "2026-09-02 16:18:00"
    },

    {
        "type": "failed_login",
        "source": "server_01",
        "timestamp": "2026-09-02 16:19:00"
    },

    {
        "type": "successful_login",
        "source": "server_01",
        "timestamp": "2026-09-02 16:20:00"
    }

]

if __name__ == "__main__":
    for event in events:
        print(event["type"])


