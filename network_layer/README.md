# Module: Network Layer
**Owner: Mohit**

## Files
| File | Purpose |
|---|---|
| `capture.py` | Live sniffing via Scapy. Pushes records to `packet_queue` |
| `parser.py` | Deep packet parser (L2–L7 field extraction) |
| `flow_tracker.py` | Groups packets into 5-tuple flows |
| `enforcer.py` | iptables + NetfilterQueue enforcement |
| `simulate_traffic.py` | Labeled attack/benign traffic generator |

## Run
```bash
sudo python -c "from network_layer.capture import start_capture; start_capture('eth0')"
```

## Data Contract (output to Ilma)
Each record pushed to `packet_queue`:
```python
{
  "src_ip": str, "dst_ip": str, "proto": str,
  "src_port": int, "dst_port": int,
  "length": int, "ttl": int, "tcp_flags": str
}
```
