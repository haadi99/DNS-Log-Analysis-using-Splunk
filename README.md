# Analyzing DNS Log Files Using Splunk SIEM

## Introduction
DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. Splunk SIEM (Security Information and Event Management) provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.


## Steps to Analyze DNS Log Files in Splunk SIEM

### 1. Search for DNS Events   
- Opened Splunk interface and navigate to the search bar.   
- Entered the following search query to retrieve DNS events   
```
index=* sourcetype=dns_sample
```

### 2. Extract Relevant Fields
- Identified key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.   
- As mentioned below,  | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b": This regex searches for common DNS-related keywords in the raw event data.
- Example extraction command:
```
index=* sourcetype=dns_sample | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```

### 3. Identify Anomalies
- Looked for unusual patterns or anomalies in DNS activity.
- Example query to identify spikes
```
index=_* OR index=* sourcetype=dns_sample  | stats count by domain
```

### 4. Find the top DNS sources
- Useed the top command to count the occurrences of each query type:   
```
index=* sourcetype=dns_sample | top domain, src_ip
```



### 5. Investigate Suspicious Domains
- Searched for domains associated with known malicious activity or suspicious behavior.
- Utilized threat intelligence feeds or reputation databases to identify malicious domains such virustotal.com
- Example search for known malicious domains:
```
index=* sourcetype=dns_sample domain="maliciousdomain.com"
```

## Conclusion
Analyzing DNS log files using Splunk SIEM enables security professionals to detect and respond to potential security incidents effectively. By understanding DNS activity and identifying anomalies, organizations can enhance their overall security posture and protect against various cyber threats.



